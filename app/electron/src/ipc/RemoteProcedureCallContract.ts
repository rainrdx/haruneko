import path from 'node:path';
import fs from 'node:fs/promises';
import { app, session, type WebContents } from 'electron';
import type { Contract } from '../../../src/rpc/Contract';
import type { IPC } from './InterProcessCommunication';
import { RemoteProcedureCallContract as Channels } from '../../../src/ipc/Channels';

export class RemoteProcedureCallContract implements Contract {

    constructor(private readonly ipc: IPC<Channels.Web, Channels.App>, private readonly webContents: WebContents) {}

    public async SetCloudFlareBypass(userAgent: string, cookies: chrome.cookies.Cookie[]): Promise<void> {
        for(const cookie of cookies) {
            try {
                await session.defaultSession.cookies.set({
                    url: `https://${ cookie.domain.replace(/^\./, '') }${ cookie.path }`,
                    name: cookie.name,
                    value: cookie.value,
                    domain: cookie.domain,
                    path: cookie.path,
                    secure: cookie.secure,
                    httpOnly: cookie.httpOnly,
                    // Enforce 1 month expiration to persist cookie after application restart
                    expirationDate: Math.round(Date.now() / 1000 + 2628000), // cookie.expirationDate
                    sameSite: cookie.sameSite,
                });
            } catch(error) {
                console.warn('Failed to set cookie:', cookie, error);
            }
        }

        if(userAgent !== this.webContents.getUserAgent()) {
            const file = path.normalize(path.resolve(app.getAppPath(), 'package.json'));
            const manifest = JSON.parse(await fs.readFile(file, 'utf-8'));
            manifest['user-agent'] = userAgent;
            await fs.writeFile(file, JSON.stringify(manifest, null, 2), 'utf-8');
            this.webContents.setUserAgent(userAgent);
        }
    }

    public async LoadMediaContainerFromURL(url: string) {
        return this.ipc.Send(Channels.Web.LoadMediaContainerFromURL, url);
    }
}