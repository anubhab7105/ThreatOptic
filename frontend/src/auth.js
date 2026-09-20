import { jsx as _jsx } from "react/jsx-runtime";
import { createContext, useCallback, useContext, useEffect, useState } from 'react';
import { clearTokens, getTokens, jget, jpost, setTokens } from './api';
const Ctx = createContext({ user: null, loading: true, login: async () => { }, register: async () => { }, logout: () => { } });
export const useAuth = () => useContext(Ctx);
export function AuthProvider({ children }) {
    const [user, setUser] = useState(null);
    const [loading, setLoading] = useState(true);
    const fetchMe = useCallback(async () => {
        if (!getTokens()) {
            setUser(null);
            setLoading(false);
            return;
        }
        try {
            setUser(await jget('/auth/me'));
        }
        catch {
            clearTokens();
            setUser(null);
        }
        finally {
            setLoading(false);
        }
    }, []);
    useEffect(() => {
        fetchMe();
        const on401 = () => {
            clearTokens();
            setUser(null);
        };
        window.addEventListener('soc:unauthorized', on401);
        return () => window.removeEventListener('soc:unauthorized', on401);
    }, [fetchMe]);
    const login = async (username, password) => {
        const pair = await jpost('/auth/login', { username, password }, { auth: false });
        setTokens(pair);
        setUser(await jget('/auth/me'));
    };
    const register = async (username, password) => {
        const pair = await jpost('/auth/register', { username, password }, { auth: false });
        setTokens(pair);
        setUser(await jget('/auth/me'));
    };
    const logout = () => {
        clearTokens();
        setUser(null);
    };
    return _jsx(Ctx.Provider, { value: { user, loading, login, register, logout }, children: children });
}
