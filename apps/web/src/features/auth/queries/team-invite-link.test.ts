import { describe, expect, it } from 'vitest';
import { teamInviteLinkFromUrl } from './auth-requests';

const login = (redirect: string) =>
  `https://macro.example/app/login?redirect=${redirect}`;

describe('teamInviteLinkFromUrl', () => {
  it('reads the link from an encoded or plain team invite redirect', () => {
    const token = 'invite-link-token';
    expect(
      teamInviteLinkFromUrl(
        login(encodeURIComponent(`/team-invite?link=${token}`))
      )
    ).toBe(token);
    expect(
      teamInviteLinkFromUrl(
        login(
          encodeURIComponent(encodeURIComponent(`/team-invite?link=${token}`))
        )
      )
    ).toBe(token);
  });

  it('ignores other redirects, emailed invites and foreign origins', () => {
    for (const redirect of [
      encodeURIComponent('/team-invite?id=abc'),
      encodeURIComponent('/documents?link=abc'),
      encodeURIComponent('//evil.example/team-invite?link=abc'),
      encodeURIComponent('https://evil.example/team-invite?link=abc'),
    ]) {
      expect(teamInviteLinkFromUrl(login(redirect))).toBeUndefined();
    }
    expect(
      teamInviteLinkFromUrl('https://macro.example/app/login')
    ).toBeUndefined();
  });
});
