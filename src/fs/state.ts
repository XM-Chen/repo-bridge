import fs from 'node:fs';
import { BridgeError } from '../errors.js';
import { atomicWriteFileSync } from './atomic.js';
import { withFileLock } from './lock.js';
export function readState<T>(file: string, initial: () => T, validate: (data: T) => boolean): T {
    let text: string;
    try {
        text = fs.readFileSync(file, 'utf8');
    }
    catch (e) {
        if ((e as NodeJS.ErrnoException).code === 'ENOENT')
            return initial();
        throw e;
    }
    try {
        const data = JSON.parse(text) as T;
        if (!validate(data))
            throw new Error('invalid state shape');
        return data;
    }
    catch (e) {
        throw new BridgeError('STATE_CORRUPT', `Cannot read state ${file}: ${(e as Error).message}. Original file preserved.`, { hint: 'Stop the bridge and restore a known-good backup.' });
    }
}
export function transact<T, R>(file: string, initial: () => T, validate: (data: T) => boolean, fn: (data: T) => R): R {
    return withFileLock(file, () => {
        const data = readState(file, initial, validate);
        const result = fn(data);
        atomicWriteFileSync(file, JSON.stringify(data), { mode: 0o600 });
        return result;
    });
}
