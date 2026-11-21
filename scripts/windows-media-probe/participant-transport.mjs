export function htmlText(value) {
  const entities={'&amp;':'&','&lt;':'<','&gt;':'>','&quot;':'"','&#x27;':"'",'&#39;':"'"};
  return value.replace(/&(?:amp|lt|gt|quot|#x27|#39);/g,x=>entities[x]);
}
// Mirror the real HTTPS Support cookie contract before forwarding this one
// participant session to the pinned HTTP and WebSocket endpoints.
export function secureParticipantCookie(setCookies) {
  const cookies = setCookies.filter(line => line.startsWith('__Host-flyw8t_support='));
  if (cookies.length !== 1) return;
  const [pair, ...attributes] = cookies[0].split(';').map(part => part.trim());
  const flags = attributes.map(attribute => attribute.toLowerCase());
  if (!/^__Host-flyw8t_support=[A-Za-z0-9_-]{43}$/.test(pair)
      || !flags.includes('secure') || !flags.includes('httponly') || !flags.includes('samesite=lax')
      || flags.filter(attribute => attribute.startsWith('path=')).join() !== 'path=/'
      || flags.some(attribute => attribute.startsWith('domain='))) return;
  return pair;
}
// Only merge a trickled candidate into the session's single video media section.
// A browser can publish an SDP answer before it finishes gathering its TURN allocation.
export function relayAnswer(answer, candidates, allocation) {
  if(!answer) return;
  if(answer.type!=='answer' || typeof answer.sdp!=='string' || answer.sdp.length>65536) throw Error('Invalid console answer.');
  const lines=answer.sdp.split(/\r?\n/);
  const media=lines.filter(line=>line.startsWith('m='));
  if(media.length!==1 || !media[0].startsWith('m=video ')) throw Error('Expected one video media section.');
  const mid=lines.find(line=>line.startsWith('a=mid:'))?.slice(6);
  const allowed=line=>{
    const parts=line.split(/\s+/);
    return line.startsWith('a=candidate:') && parts[2]?.toLowerCase()==='udp' && parts[4]===allocation && parts[6]==='typ' && parts[7]==='relay';
  };
  const offered=lines.filter(allowed);
  for(const c of candidates) {
    if(!c || typeof c.candidate!=='string' || c.candidate.length>2048 || /[\r\n]/.test(c.candidate)) continue;
    if(c.sdpMid!=null && c.sdpMid!==mid || c.sdpMLineIndex!=null && c.sdpMLineIndex!==0) continue;
    const line='a='+c.candidate;
    if(allowed(line)) offered.push(line);
  }
  if(!offered.length) return;
  return {type:'answer',sdp:[...lines.filter(line=>line && line!=='a=end-of-candidates' && !line.startsWith('a=candidate:')),...new Set(offered),'a=end-of-candidates',''].join('\r\n')};
}
