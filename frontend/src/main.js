import { jsx as _jsx, jsxs as _jsxs } from "react/jsx-runtime";
import { useEffect, useState } from 'react';
import { createRoot } from 'react-dom/client';
import './theme.css';
import { AuthProvider, useAuth } from './auth';
import { Dashboard, EmailView, Cases, LoginPage } from './pages';
function Shell() {
    const { user, loading, logout } = useAuth();
    const [hash, setHash] = useState(window.location.hash || '#/');
    const [health, setHealth] = useState('unknown');
    useEffect(() => {
        const f = () => setHash(window.location.hash || '#/');
        window.addEventListener('hashchange', f);
        return () => window.removeEventListener('hashchange', f);
    }, []);
    useEffect(() => {
        fetch('/health')
            .then((r) => setHealth(r.ok ? 'ok' : 'down'))
            .catch(() => setHealth('down'));
    }, [hash]);
    const route = hash.startsWith('#/email/')
        ? 'email'
        : hash.startsWith('#/cases')
            ? 'cases'
            : 'dash';
    if (loading) {
        return (_jsxs("div", { children: [_jsx("nav", { className: "nav", children: _jsxs("span", { className: "brand", children: [_jsx("span", { children: "\u25C8" }), " Email Forensics SOC"] }) }), _jsx("div", { className: "page", children: _jsx("div", { className: "skel", style: { height: 120 } }) })] }));
    }
    if (!user)
        return _jsx(LoginPage, {});
    return (_jsxs("div", { children: [_jsxs("nav", { className: "nav", children: [_jsxs("span", { className: "brand", children: [_jsx("span", { children: "\u25C8" }), " Email Forensics SOC"] }), _jsx("a", { className: `nl${route === 'dash' ? ' active' : ''}`, href: "#/", children: "Dashboard" }), _jsx("a", { className: `nl${route === 'cases' ? ' active' : ''}`, href: "#/cases", children: "Cases" }), _jsx("span", { className: "spacer" }), _jsxs("span", { className: "health", title: `${user.username} · ${user.role}`, children: [user.username, " (", user.role, ")"] }), _jsx("a", { className: "nl", href: "#/", onClick: (e) => { e.preventDefault(); logout(); window.location.hash = '#/'; }, children: "Sign out" }), _jsxs("span", { className: "health", title: "backend reachability", children: [_jsx("span", { className: "dot", style: { background: health === 'ok' ? '#22c55e' : health === 'down' ? '#ef4444' : '#eab308' } }), health === 'ok' ? 'API online' : health === 'down' ? 'API unreachable' : 'checking API…'] })] }), route === 'email' ? (_jsx(EmailView, { id: hash.replace('#/email/', '') })) : route === 'cases' ? (_jsx(Cases, {})) : (_jsx(Dashboard, {})), _jsx("div", { className: "footer", children: "AI Email Threat Detection \u00B7 GeoLocation \u00B7 Forensic Intelligence \u2014 chain-of-custody reports via PDF/JSON" })] }));
}
createRoot(document.getElementById('root')).render(_jsx(AuthProvider, { children: _jsx(Shell, {}) }));
