//! Model-based property test of the job delivery protocol.
//!
//! A simulated server (the real `flyw8t_domain::job::decide` and transition table) talks to a
//! simulated agent (the real on-disk `Journal`) over a lossy, duplicating, disconnecting
//! channel, with agent crashes, cancels and deadline expiries injected at random. After every
//! step, safety invariants must hold; after a final fault-free "settle" phase, liveness
//! invariants must hold. See docs/reliability.md for what this does and does not prove.
//!
//! What is modelled from the code, not re-implemented: the journal (real files on disk), the
//! server's report decision and legal-transition table. What is modelled by hand, mirroring
//! `connection.rs` and `jobs.rs`: the agent's offer/cancel handling, the server's dispatch
//! and cancel rules, and the sweeper's deadline rules. Divergence there is the model's main
//! risk and is checked by the end-to-end tests instead.

use flyw8t_agent::journal::{Accept, EntryState, Journal};
use flyw8t_domain::job::{decide, state_for_outcome, ExecState, Report};
use flyw8t_protocol::messages::{ExecOutcome, Finished, JobPhase, JobReport, NotAccepted};
use flyw8t_protocol::Action;
use proptest::prelude::*;
use std::collections::{HashMap, HashSet, VecDeque};
use time::OffsetDateTime;
use uuid::Uuid;

#[derive(Debug, Clone)]
enum Op {
    Create,
    Connect,
    Disconnect,
    DeliverToAgent,
    DeliverToServer,
    DropToAgent,
    DropToServer,
    DuplicateToAgent,
    DuplicateToServer,
    StartJob(u8),
    FinishJob(u8, u8),
    Crash,
    Cancel(u8),
    Deadline(u8),
    /// Time passes: the server re-offers unacknowledged jobs and the agent re-sends
    /// unacknowledged final reports (heartbeat).
    Tick,
}

fn op() -> impl Strategy<Value = Op> {
    prop_oneof![
        3 => Just(Op::Create),
        3 => Just(Op::Connect),
        2 => Just(Op::Disconnect),
        8 => Just(Op::DeliverToAgent),
        8 => Just(Op::DeliverToServer),
        1 => Just(Op::DropToAgent),
        1 => Just(Op::DropToServer),
        1 => Just(Op::DuplicateToAgent),
        1 => Just(Op::DuplicateToServer),
        4 => any::<u8>().prop_map(Op::StartJob),
        4 => (any::<u8>(), any::<u8>()).prop_map(|(a, b)| Op::FinishJob(a, b)),
        1 => Just(Op::Crash),
        1 => any::<u8>().prop_map(Op::Cancel),
        1 => any::<u8>().prop_map(Op::Deadline),
        2 => Just(Op::Tick),
    ]
}

#[derive(Debug, Clone)]
enum ToAgent {
    Offer(Uuid),
    Cancel(Uuid),
    Ack(Uuid),
}

#[derive(Debug)]
struct ServerJob {
    id: Uuid,
    state: ExecState,
    cancel_requested: bool,
    last_dispatch_conn: Option<u32>,
    first_terminal: Option<ExecState>,
    cancelled_before_dispatch: bool,
}

struct Sim {
    _dir: tempfile::TempDir,
    journal_dir: std::path::PathBuf,
    journal: Journal,
    jobs: Vec<ServerJob>,
    conn: Option<u32>,
    next_conn: u32,
    to_agent: VecDeque<ToAgent>,
    to_server: VecDeque<JobReport>,
    /// In agent memory only (lost on crash): accepted but not started, and running.
    pending: Vec<Uuid>,
    running: Vec<Uuid>,
    cancel_tokens: HashSet<Uuid>,
    executions: HashMap<Uuid, u32>,
}

fn finished(outcome: ExecOutcome, started: bool) -> Finished {
    Finished {
        outcome,
        started_at: started.then(OffsetDateTime::now_utc),
        finished_at: OffsetDateTime::now_utc(),
        stdout: None,
        stderr: None,
        structured: None,
    }
}

impl Sim {
    fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let journal_dir = dir.path().join("journal");
        let journal = Journal::open(&journal_dir).unwrap();
        Sim {
            _dir: dir,
            journal_dir,
            journal,
            jobs: vec![],
            conn: None,
            next_conn: 1,
            to_agent: VecDeque::new(),
            to_server: VecDeque::new(),
            pending: vec![],
            running: vec![],
            cancel_tokens: HashSet::new(),
            executions: HashMap::new(),
        }
    }

    fn pick(&self, n: u8) -> Option<usize> {
        (!self.jobs.is_empty()).then(|| n as usize % self.jobs.len())
    }

    fn set_state(&mut self, i: usize, to: ExecState) {
        let j = &mut self.jobs[i];
        assert!(
            j.state.can_transition_to(to),
            "model drove an illegal transition {:?} -> {to:?}",
            j.state
        );
        j.state = to;
        if to.is_terminal() && j.first_terminal.is_none() {
            j.first_terminal = Some(to);
        }
    }

    // ---- agent side (mirrors connection.rs) ----

    fn agent_emit(&mut self, report: JobReport) {
        // A report produced while no session is draining is dropped; the journal re-sends.
        if self.conn.is_some() {
            self.to_server.push_back(report);
        }
    }

    fn agent_receive(&mut self, msg: ToAgent) {
        match msg {
            ToAgent::Offer(id) => {
                if let Some(entry) = self.journal.get(id) {
                    return self.agent_emit(entry.report());
                }
                // Mirrors MAX_CONCURRENT_JOBS: a full agent declines without journaling.
                if self.pending.len() + self.running.len() >= 2 {
                    return self.agent_emit(JobReport {
                        job_id: id,
                        phase: JobPhase::NotAccepted {
                            reason: NotAccepted::Busy,
                        },
                    });
                }
                match self.journal.accept(id, &Action::NetIpconfig, 30).unwrap() {
                    Accept::New => {
                        self.pending.push(id);
                        self.agent_emit(JobReport {
                            job_id: id,
                            phase: JobPhase::Accepted,
                        });
                    }
                    Accept::Known(e) => self.agent_emit(e.report()),
                }
            }
            ToAgent::Cancel(id) => {
                if self.pending.contains(&id) || self.running.contains(&id) {
                    self.cancel_tokens.insert(id);
                    return;
                }
                let entry = match self.journal.get(id) {
                    Some(e) => e,
                    None => self.journal.cancel_unknown(id).unwrap(),
                };
                self.agent_emit(entry.report());
            }
            ToAgent::Ack(id) => self.journal.mark_acked(id).unwrap(),
        }
    }

    fn agent_start(&mut self, n: u8) {
        if self.pending.is_empty() {
            return;
        }
        let id = self.pending.remove(n as usize % self.pending.len());
        if self.cancel_tokens.contains(&id) {
            let f = finished(ExecOutcome::Cancelled { started: false }, false);
            self.journal.finish(id, f.clone()).unwrap();
            return self.agent_emit(JobReport {
                job_id: id,
                phase: JobPhase::Finished(Box::new(f)),
            });
        }
        let at = OffsetDateTime::now_utc();
        self.journal.mark_started(id, at).unwrap();
        *self.executions.entry(id).or_default() += 1;
        self.running.push(id);
        self.agent_emit(JobReport {
            job_id: id,
            phase: JobPhase::Started { at },
        });
    }

    fn agent_finish(&mut self, n: u8, kind: u8) {
        if self.running.is_empty() {
            return;
        }
        let id = self.running.remove(n as usize % self.running.len());
        let outcome = if self.cancel_tokens.contains(&id) {
            ExecOutcome::Cancelled { started: true }
        } else {
            match kind % 4 {
                0 | 1 => ExecOutcome::Exited { code: 0 },
                2 => ExecOutcome::TimedOut,
                _ => ExecOutcome::Failed {
                    error: "boom".into(),
                },
            }
        };
        let f = finished(outcome, true);
        self.journal.finish(id, f.clone()).unwrap();
        self.agent_emit(JobReport {
            job_id: id,
            phase: JobPhase::Finished(Box::new(f)),
        });
    }

    fn agent_crash(&mut self) {
        self.pending.clear();
        self.running.clear();
        self.cancel_tokens.clear();
        self.disconnect();
        self.journal = Journal::open(&self.journal_dir).unwrap();
    }

    // ---- server side (mirrors jobs.rs) ----

    fn dispatch(&mut self, new_connection: bool, stale: bool) {
        let Some(conn) = self.conn else { return };
        for i in 0..self.jobs.len() {
            let j = &self.jobs[i];
            let id = j.id;
            match j.state {
                ExecState::Queued if !j.cancel_requested => {
                    self.set_state(i, ExecState::Dispatched);
                    self.jobs[i].last_dispatch_conn = Some(conn);
                    self.to_agent.push_back(ToAgent::Offer(id));
                }
                ExecState::Dispatched
                    if !j.cancel_requested
                        && ((new_connection && j.last_dispatch_conn != Some(conn)) || stale) =>
                {
                    self.jobs[i].last_dispatch_conn = Some(conn);
                    self.to_agent.push_back(ToAgent::Offer(id));
                }
                _ => {}
            }
        }
        if new_connection || stale {
            for j in &self.jobs {
                if j.cancel_requested
                    && (j.state.is_in_flight() || j.state == ExecState::OutcomeUnknown)
                {
                    self.to_agent.push_back(ToAgent::Cancel(j.id));
                }
            }
        }
    }

    fn server_receive(&mut self, r: JobReport) {
        let i = self
            .jobs
            .iter()
            .position(|j| j.id == r.job_id)
            .expect("report for a known job");
        let reduced = match &r.phase {
            JobPhase::Accepted => Report::Accepted,
            JobPhase::NotAccepted { reason } => Report::NotAccepted {
                retryable: matches!(reason, NotAccepted::Busy | NotAccepted::StorageError),
            },
            JobPhase::Started { .. } => Report::Started,
            JobPhase::Finished(f) => Report::Finished(state_for_outcome(&f.outcome)),
        };
        let d = decide(self.jobs[i].state, reduced);
        if d.implied_dispatch {
            self.set_state(i, ExecState::Dispatched);
        }
        if let Some(to) = d.to {
            self.set_state(i, to);
        }
        if d.ack && self.conn.is_some() {
            self.to_agent.push_back(ToAgent::Ack(r.job_id));
        }
    }

    fn cancel(&mut self, n: u8) {
        let Some(i) = self.pick(n) else { return };
        let st = self.jobs[i].state;
        if st.is_pre_dispatch() {
            self.set_state(i, ExecState::Cancelled);
            self.jobs[i].cancelled_before_dispatch = true;
        } else if !st.is_terminal() && !self.jobs[i].cancel_requested {
            self.jobs[i].cancel_requested = true;
            if self.conn.is_some() {
                self.to_agent.push_back(ToAgent::Cancel(self.jobs[i].id));
            }
        }
    }

    fn deadline(&mut self, n: u8) {
        let Some(i) = self.pick(n) else { return };
        match self.jobs[i].state {
            ExecState::Queued => self.set_state(i, ExecState::Expired),
            s if s.is_in_flight() => self.set_state(i, ExecState::OutcomeUnknown),
            _ => {}
        }
    }

    fn connect(&mut self) {
        if self.conn.is_some() {
            return;
        }
        self.conn = Some(self.next_conn);
        self.next_conn += 1;
        for r in self.journal.unreported() {
            self.to_server.push_back(r);
        }
        self.dispatch(true, false);
    }

    fn disconnect(&mut self) {
        self.conn = None;
        self.to_agent.clear();
        self.to_server.clear();
    }

    fn apply(&mut self, op: Op) {
        match op {
            Op::Create if self.jobs.len() < 4 => {
                self.jobs.push(ServerJob {
                    id: Uuid::new_v4(),
                    state: ExecState::Queued,
                    cancel_requested: false,
                    last_dispatch_conn: None,
                    first_terminal: None,
                    cancelled_before_dispatch: false,
                });
                self.dispatch(false, false);
            }
            Op::Create => {}
            Op::Connect => self.connect(),
            Op::Disconnect => self.disconnect(),
            Op::DeliverToAgent => {
                if let Some(m) = self.to_agent.pop_front() {
                    self.agent_receive(m);
                }
            }
            Op::DeliverToServer => {
                if let Some(r) = self.to_server.pop_front() {
                    self.server_receive(r);
                }
            }
            Op::DropToAgent => drop(self.to_agent.pop_front()),
            Op::DropToServer => drop(self.to_server.pop_front()),
            Op::DuplicateToAgent => {
                if let Some(m) = self.to_agent.front().cloned() {
                    self.to_agent.push_back(m);
                }
            }
            Op::DuplicateToServer => {
                if let Some(m) = self.to_server.front().cloned() {
                    self.to_server.push_back(m);
                }
            }
            Op::StartJob(n) => self.agent_start(n),
            Op::FinishJob(n, k) => self.agent_finish(n, k),
            Op::Crash => self.agent_crash(),
            Op::Cancel(n) => self.cancel(n),
            Op::Deadline(n) => self.deadline(n),
            Op::Tick => self.tick(),
        }
    }

    fn tick(&mut self) {
        if self.conn.is_none() {
            return;
        }
        self.dispatch(false, true);
        for r in self.journal.unreported() {
            if matches!(r.phase, JobPhase::Finished(_)) {
                self.to_server.push_back(r);
            }
        }
    }

    /// Run with no faults until nothing moves.
    fn settle(&mut self) {
        self.connect();
        let mut idle_ticks = 0;
        for _ in 0..1000 {
            if let Some(m) = self.to_agent.pop_front() {
                self.agent_receive(m);
            } else if let Some(r) = self.to_server.pop_front() {
                self.server_receive(r);
            } else if !self.pending.is_empty() {
                self.agent_start(0);
            } else if !self.running.is_empty() {
                self.agent_finish(0, 0);
            } else if idle_ticks < 3 && self.unsettled() {
                idle_ticks += 1;
                self.tick();
            } else {
                return;
            }
        }
        panic!("system did not settle within 1000 steps");
    }

    fn unsettled(&self) -> bool {
        self.jobs.iter().any(|j| j.state.is_in_flight()) || !self.journal.unreported().is_empty()
    }

    fn check_safety(&self) {
        for j in &self.jobs {
            let runs = self.executions.get(&j.id).copied().unwrap_or(0);
            assert!(runs <= 1, "job executed {runs} times");
            if j.state == ExecState::Completed {
                assert_eq!(runs, 1, "Completed without an execution");
            }
            if j.state == ExecState::Expired || j.cancelled_before_dispatch {
                assert_eq!(runs, 0, "{:?} job was executed", j.state);
            }
            if let Some(EntryState::Finished { report }) = self.journal.get(j.id).map(|e| e.state) {
                if matches!(
                    report.outcome,
                    ExecOutcome::NotStarted { .. } | ExecOutcome::Cancelled { started: false }
                ) {
                    assert_eq!(
                        runs, 0,
                        "device claims {:?} but executed it",
                        report.outcome
                    );
                }
            }
            if let Some(t) = j.first_terminal {
                assert_eq!(j.state, t, "terminal state {t:?} changed to {:?}", j.state);
            }
        }
    }

    fn check_liveness(&self) {
        for j in &self.jobs {
            assert!(
                !j.state.is_in_flight(),
                "job stuck in {:?} after settling (cancel_requested={})",
                j.state,
                j.cancel_requested
            );
            let agent_final = self.journal.get(j.id).and_then(|e| match e.state {
                EntryState::Finished { report } => Some(report.outcome),
                _ => None,
            });
            if j.state == ExecState::OutcomeUnknown {
                // Unknown may remain only when the device has no conclusive evidence.
                if let Some(o) = &agent_final {
                    assert!(
                        matches!(o, ExecOutcome::Interrupted { .. }),
                        "device holds conclusive evidence {o:?} but server still says unknown"
                    );
                }
            }
            if let (Some(o), None) = (
                &agent_final,
                j.first_terminal
                    .filter(|_| j.state != ExecState::OutcomeUnknown),
            ) {
                assert_eq!(
                    j.state,
                    state_for_outcome(o),
                    "server disagrees with device evidence"
                );
            }
        }
        assert!(
            self.journal.unreported().is_empty(),
            "device still holds unacknowledged reports"
        );
    }
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 400, max_shrink_iters: 2000, ..ProptestConfig::default() })]

    #[test]
    fn delivery_is_at_most_once_and_converges(ops in prop::collection::vec(op(), 1..80)) {
        let mut sim = Sim::new();
        for op in ops {
            sim.apply(op);
            sim.check_safety();
        }
        sim.settle();
        sim.check_safety();
        sim.check_liveness();
    }
}
