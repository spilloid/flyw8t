import { createSocket } from 'node:dgram';
import { lookup } from 'node:dns/promises';
import { isIPv4 } from 'node:net';
import { htmlText } from './participant-transport.mjs';

export function supportOrigin(input) {
  if (typeof input !== 'string' || input.length > 256 ||
      !/^https:\/\/[^/?#\\@\s]+\/?$/i.test(input)) throw Error('Enter the HTTPS address of your Flyw8t console.');
  let url;
  try { url = new URL(input); } catch { throw Error('Enter the HTTPS address of your Flyw8t console.'); }
  return url.origin;
}

function usableAddress(value) {
  if (!isIPv4(value)) return false;
  const [first, second] = value.split('.').map(Number);
  return first > 0 && first < 224 && first !== 127 && !(first === 169 && second === 254);
}

// The consent page and the technician use the deployment's configured ICE servers.
// This beta supports one IPv4 UDP relay whose allocation and listener share an IP.
export function udpTurn(tag) {
  const encoded = tag.match(/\bdata-ice="([^"]*)"/)?.[1];
  if (!encoded || encoded.length > 8192) throw Error('Missing ICE settings.');
  const servers = JSON.parse(htmlText(encoded));
  if (!Array.isArray(servers)) throw Error('Invalid ICE settings.');
  for (const server of servers) {
    if (typeof server?.username !== 'string' || !server.username.length || server.username.length > 512 ||
        typeof server.credential !== 'string' || !server.credential.length || server.credential.length > 512) continue;
    for (const url of [server.urls].flat()) {
      if (typeof url !== 'string') continue;
      const parts = /^turn:([a-z0-9.-]+)(?::([0-9]{1,5}))?(?:\?transport=udp)?$/i.exec(url);
      if (!parts || !parts[1].split('.').every(label => /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/i.test(label))) continue;
      const port = Number(parts[2] ?? 3478);
      if (port > 0 && port <= 65535) return {host:parts[1], port, username:server.username, credential:server.credential};
    }
  }
  throw Error('The console must provide an authenticated IPv4 UDP TURN relay.');
}

async function interfaceFor(server, port) {
  const socket = createSocket('udp4');
  try {
    return await new Promise((resolve, reject) => {
      socket.once('error', reject);
      socket.connect(port, server, () => resolve(socket.address().address));
    });
  } finally { socket.close(); }
}

export async function publicRelay(tag, resolveHost = host => lookup(host, {family:4}), route = interfaceFor) {
  const {host, port, username, credential} = udpTurn(tag);
  const {address} = await resolveHost(host);
  if (!usableAddress(address)) throw Error('The video relay needs a routable IPv4 address.');
  const bind = await route(address, port);
  if (!usableAddress(bind)) throw Error('Windows has no IPv4 route to the video relay.');
  return {server:address, allocation:address, bind, port, username, credential};
}

export async function publicConnection(input) {
  const origin = supportOrigin(input);
  const { fetch, WebSocket } = await import('undici');
  return {
    origin,
    request(target, options) {
      if (![origin + '/s', origin + '/s/session'].includes(target)) throw Error('Unknown support endpoint.');
      return fetch(target, {...options, redirect:'manual'});
    },
    socket(cookie) {
      return new WebSocket(origin.replace(/^https:/, 'wss:') + '/api/support/participant/ws',
        {headers:{Origin:origin, Cookie:cookie}});
    },
    relay:publicRelay,
  };
}
