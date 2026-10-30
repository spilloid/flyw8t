------------------------------ MODULE JobDelivery ------------------------------
(***************************************************************************)
(* One flyw8t job between the server and one agent.                         *)
(*                                                                         *)
(* Channels are SETS: delivering a message does not remove it, so every    *)
(* message may be delivered any number of times, in any order (arbitrary   *)
(* duplication and reordering). Lose removes a message (loss). Disconnect *)
(* empties both channels; AgentCrash also loses the agent's memory, and   *)
(* the journal recovers as journal.rs does. Server deadlines (expiry,      *)
(* silence) fire at any time, which over-approximates real clocks.         *)
(*                                                                         *)
(* Server report handling mirrors flyw8t_domain::job::decide; agent        *)
(* handling mirrors crates/flyw8t-agent/src/connection.rs. This is a       *)
(* hand translation: the Rust property test (crates/flyw8t-agent/tests/    *)
(* model.rs) exercises the real journal and the real decide function.      *)
(***************************************************************************)
EXTENDS Naturals

VARIABLES
    sstate,       \* server execution state
    cancelReq,    \* a cancel was requested after dispatch
    preCancelled, \* cancelled before dispatch
    journal,      \* agent journal entry: "none" "accepted" "started" "finished"
    jfinal,       \* the journal's final outcome, once finished
    acked,        \* server acknowledged the final report
    inMemory,     \* agent holds a live task for the job (lost on crash)
    cancelTok,    \* agent-side cancel token for the live task
    execs,        \* times the action actually executed on the device
    connected,
    toAgent,      \* SUBSET {"offer", "cancel", "ack"}
    toServer      \* SUBSET Reports

vars == <<sstate, cancelReq, preCancelled, journal, jfinal, acked, inMemory,
          cancelTok, execs, connected, toAgent, toServer>>

InFlight == {"dispatched", "acknowledged", "running"}
Terminal == {"completed", "failed", "timed_out", "cancelled", "expired"}
Finals   == {"completed", "failed", "timed_out", "cancelled_started",
             "cancelled_nostart", "notstarted", "interrupted"}
Reports  == {"accepted", "started"} \cup {"f_" \o f : f \in Finals}

TypeOK ==
    /\ sstate \in {"queued", "outcome_unknown"} \cup InFlight \cup Terminal
    /\ journal \in {"none", "accepted", "started", "finished"}
    /\ jfinal \in Finals \cup {"none"}
    /\ execs \in 0..2
    /\ toAgent \subseteq {"offer", "cancel", "ack"}
    /\ toServer \subseteq Reports

Init ==
    /\ sstate = "queued" /\ cancelReq = FALSE /\ preCancelled = FALSE
    /\ journal = "none" /\ jfinal = "none" /\ acked = FALSE
    /\ inMemory = FALSE /\ cancelTok = FALSE /\ execs = 0
    /\ connected = FALSE /\ toAgent = {} /\ toServer = {}

\* The agent's latest report for its journal entry.
JournalReport ==
    CASE journal = "accepted" -> "accepted"
      [] journal = "started"  -> "started"
      [] journal = "finished" -> "f_" \o jfinal

AgentSay(r) == IF connected THEN toServer' = toServer \cup {r} ELSE UNCHANGED toServer

----------------------------------------------------------------------------
\* Server

Dispatch ==
    /\ connected /\ sstate = "queued" /\ ~cancelReq
    /\ sstate' = "dispatched" /\ toAgent' = toAgent \cup {"offer"}
    /\ UNCHANGED <<cancelReq, preCancelled, journal, jfinal, acked, inMemory, cancelTok, execs, connected, toServer>>

\* New connection, or redelivery interval elapsed.
Redeliver ==
    /\ connected /\ sstate = "dispatched" /\ ~cancelReq
    /\ toAgent' = toAgent \cup {"offer"}
    /\ UNCHANGED <<sstate, cancelReq, preCancelled, journal, jfinal, acked, inMemory, cancelTok, execs, connected, toServer>>

ResendCancel ==
    /\ connected /\ cancelReq /\ sstate \in InFlight \cup {"outcome_unknown"}
    /\ toAgent' = toAgent \cup {"cancel"}
    /\ UNCHANGED <<sstate, cancelReq, preCancelled, journal, jfinal, acked, inMemory, cancelTok, execs, connected, toServer>>

Cancel ==
    /\ ~cancelReq /\ sstate \notin Terminal
    /\ IF sstate = "queued"
         THEN /\ sstate' = "cancelled" /\ preCancelled' = TRUE
              /\ UNCHANGED <<cancelReq, toAgent>>
         ELSE /\ cancelReq' = TRUE
              /\ toAgent' = IF connected THEN toAgent \cup {"cancel"} ELSE toAgent
              /\ UNCHANGED <<sstate, preCancelled>>
    /\ UNCHANGED <<journal, jfinal, acked, inMemory, cancelTok, execs, connected, toServer>>

Expire ==
    /\ sstate = "queued" /\ sstate' = "expired"
    /\ UNCHANGED <<cancelReq, preCancelled, journal, jfinal, acked, inMemory, cancelTok, execs, connected, toAgent, toServer>>

Silence ==
    /\ sstate \in InFlight /\ sstate' = "outcome_unknown"
    /\ UNCHANGED <<cancelReq, preCancelled, journal, jfinal, acked, inMemory, cancelTok, execs, connected, toAgent, toServer>>

Target(r) ==
    CASE r = "f_completed"                                  -> "completed"
      [] r \in {"f_failed", "f_notstarted"}                 -> "failed"
      [] r = "f_timed_out"                                  -> "timed_out"
      [] r \in {"f_cancelled_started", "f_cancelled_nostart"} -> "cancelled"
      [] r = "f_interrupted"                                -> "outcome_unknown"

IsFinal(r) == r \notin {"accepted", "started"}

\* domain::job::decide, applied (including the implied dispatch from "queued").
ServerReceive ==
    /\ connected
    /\ \E r \in toServer :
        LET eff == IF sstate = "queued" THEN "dispatched" ELSE sstate IN
        /\ sstate' =
            IF sstate \in Terminal THEN sstate
            ELSE CASE r = "accepted" -> IF eff = "dispatched" THEN "acknowledged" ELSE sstate
                   [] r = "started"  -> IF eff \in {"dispatched", "acknowledged"} THEN "running" ELSE sstate
                   [] OTHER -> IF eff = "outcome_unknown" /\ Target(r) = "outcome_unknown"
                               THEN sstate ELSE Target(r)
        /\ toAgent' = IF IsFinal(r) THEN toAgent \cup {"ack"} ELSE toAgent
    /\ UNCHANGED <<cancelReq, preCancelled, journal, jfinal, acked, inMemory, cancelTok, execs, connected, toServer>>

----------------------------------------------------------------------------
\* Agent

AgentOffer ==
    /\ connected /\ "offer" \in toAgent
    /\ IF journal # "none"
         THEN /\ toServer' = toServer \cup {JournalReport}
              /\ UNCHANGED <<journal, inMemory>>
         ELSE /\ journal' = "accepted" /\ inMemory' = TRUE
              /\ toServer' = toServer \cup {"accepted"}
    /\ UNCHANGED <<sstate, cancelReq, preCancelled, jfinal, acked, cancelTok, execs, connected, toAgent>>

AgentCancel ==
    /\ connected /\ "cancel" \in toAgent
    /\ IF inMemory
         THEN /\ cancelTok' = TRUE /\ UNCHANGED <<journal, jfinal, toServer>>
         ELSE IF journal = "none"
           THEN /\ journal' = "finished" /\ jfinal' = "cancelled_nostart"
                /\ toServer' = toServer \cup {"f_cancelled_nostart"}
                /\ UNCHANGED cancelTok
           ELSE /\ toServer' = toServer \cup {JournalReport}
                /\ UNCHANGED <<journal, jfinal, cancelTok>>
    /\ UNCHANGED <<sstate, cancelReq, preCancelled, acked, inMemory, execs, connected, toAgent>>

AgentAck ==
    /\ connected /\ "ack" \in toAgent /\ journal = "finished"
    /\ acked' = TRUE
    /\ UNCHANGED <<sstate, cancelReq, preCancelled, journal, jfinal, inMemory, cancelTok, execs, connected, toAgent, toServer>>

AgentStart ==
    /\ inMemory /\ journal = "accepted"
    /\ IF cancelTok
         THEN /\ journal' = "finished" /\ jfinal' = "cancelled_nostart" /\ inMemory' = FALSE
              /\ AgentSay("f_cancelled_nostart") /\ UNCHANGED execs
         ELSE /\ journal' = "started" /\ execs' = execs + 1
              /\ AgentSay("started") /\ UNCHANGED <<jfinal, inMemory>>
    /\ UNCHANGED <<sstate, cancelReq, preCancelled, acked, cancelTok, connected, toAgent>>

AgentFinish ==
    /\ inMemory /\ journal = "started"
    /\ \E f \in (IF cancelTok THEN {"cancelled_started"} ELSE {"completed", "failed", "timed_out"}) :
         /\ jfinal' = f /\ AgentSay("f_" \o f)
    /\ journal' = "finished" /\ inMemory' = FALSE
    /\ UNCHANGED <<sstate, cancelReq, preCancelled, acked, cancelTok, execs, connected, toAgent>>

\* Heartbeat: re-send an unacknowledged final report.
AgentResend ==
    /\ connected /\ journal = "finished" /\ ~acked
    /\ toServer' = toServer \cup {JournalReport}
    /\ UNCHANGED <<sstate, cancelReq, preCancelled, journal, jfinal, acked, inMemory, cancelTok, execs, connected, toAgent>>

AgentCrash ==
    /\ inMemory' = FALSE /\ cancelTok' = FALSE /\ connected' = FALSE
    /\ toAgent' = {} /\ toServer' = {}
    /\ CASE journal = "accepted" -> journal' = "finished" /\ jfinal' = "notstarted"
         [] journal = "started"  -> journal' = "finished" /\ jfinal' = "interrupted"
         [] OTHER                -> UNCHANGED <<journal, jfinal>>
    /\ UNCHANGED <<sstate, cancelReq, preCancelled, acked, execs>>

----------------------------------------------------------------------------
\* Network

Connect ==
    /\ ~connected /\ connected' = TRUE
    /\ toServer' = IF journal # "none" /\ ~acked THEN {JournalReport} ELSE {}
    /\ UNCHANGED <<sstate, cancelReq, preCancelled, journal, jfinal, acked, inMemory, cancelTok, execs, toAgent>>

Disconnect ==
    /\ connected /\ connected' = FALSE /\ toAgent' = {} /\ toServer' = {}
    /\ UNCHANGED <<sstate, cancelReq, preCancelled, journal, jfinal, acked, inMemory, cancelTok, execs>>

Lose ==
    \/ \E m \in toAgent : toAgent' = toAgent \ {m} /\ UNCHANGED toServer
    \/ \E m \in toServer : toServer' = toServer \ {m} /\ UNCHANGED toAgent
    /\ UNCHANGED <<sstate, cancelReq, preCancelled, journal, jfinal, acked, inMemory, cancelTok, execs, connected>>

Next ==
    \/ Dispatch \/ Redeliver \/ ResendCancel \/ Cancel \/ Expire \/ Silence \/ ServerReceive
    \/ AgentOffer \/ AgentCancel \/ AgentAck \/ AgentStart \/ AgentFinish \/ AgentResend \/ AgentCrash
    \/ Connect \/ Disconnect \/ Lose

Spec == Init /\ [][Next]_vars

----------------------------------------------------------------------------
\* Safety

AtMostOnce            == execs <= 1
NoSuccessWithoutRun   == sstate = "completed" => execs = 1
ExpiredNeverRan       == sstate = "expired" => execs = 0
PreCancelNeverRan     == preCancelled => execs = 0
NotStartedIsTrue      == jfinal \in {"notstarted", "cancelled_nostart"} => execs = 0
SuccessMatchesDevice  == sstate = "completed" => jfinal = "completed"

TerminalIsStable == [][sstate \in Terminal => sstate' = sstate]_vars
UnknownOnlyResolvesToFinal ==
    [][sstate = "outcome_unknown" /\ sstate' # sstate => sstate' \in Terminal \ {"expired"}]_vars

=============================================================================
