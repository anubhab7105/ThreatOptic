import { jsx as _jsx, jsxs as _jsxs } from "react/jsx-runtime";
import { useEffect, useState } from 'react';
import { createRoot } from 'react-dom/client';
import { Dashboard, EmailView, Cases } from './pages';
function Router() {
    const [hash, setHash] = useState(window.location.hash);
    useEffect(() => {
        const f = () => setHash(window.location.hash);
        window.addEventListener('hashchange', f);
        return () => window.removeEventListener('hashchange', f);
    }, []);
    return (_jsxs("div", { children: [_jsxs("nav", { style: { padding: 12, background: '#111827' }, children: [_jsx("a", { href: "#/", style: { marginRight: 16 }, children: "Dashboard" }), _jsx("a", { href: "#/cases", style: { marginRight: 16 }, children: "Cases" }), _jsx("span", { style: { opacity: 0.7 }, children: "AI Email Threat & Forensics" })] }), hash.startsWith('#/email/') ? _jsx(EmailView, { id: hash.replace('#/email/', '') })
                : hash.startsWith('#/cases') ? _jsx(Cases, {})
                    : _jsx(Dashboard, {})] }));
}
createRoot(document.getElementById('root')).render(_jsx(Router, {}));
