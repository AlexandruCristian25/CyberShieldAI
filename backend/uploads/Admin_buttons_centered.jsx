import { useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";
import axios from "axios";
import AssistantBubble from "../components/AssistantBubble";

import {
    Chart as ChartJS,
    CategoryScale,
    LinearScale,
    BarElement,
    ArcElement,
    Tooltip,
    Legend
} from "chart.js";

import {
    Bar,
    Doughnut
} from "react-chartjs-2";

ChartJS.register(
    CategoryScale,
    LinearScale,
    BarElement,
    ArcElement,
    Tooltip,
    Legend
);

const API_URL = "http://127.0.0.1:5000";

export default function Admin() {

    const navigate = useNavigate();

    const [users, setUsers] = useState([]);
    const [auditLogs, setAuditLogs] = useState([]);
    const [analytics, setAnalytics] = useState({
        total_users: 0,
        total_admins: 0,
        blocked_users: 0,
        total_scans: 0,
        threats_detected: 0,
        login_attempts: 0,
        successful_logins: 0,
        failed_logins: 0,
        brute_force_blocks: 0
    });

    const [notifications, setNotifications] = useState([]);
    const [lastAuditId, setLastAuditId] = useState(null);
    const [error, setError] = useState("");

    const admin = JSON.parse(
        localStorage.getItem("user")
    );

    useEffect(() => {

        if (!admin || admin.role !== "admin") {
            navigate("/dashboard");
            return;
        }

        loadUsers();
        loadAuditLogs();
        loadAnalytics();

        const interval = setInterval(() => {
            loadUsers();
            loadAuditLogs(true);
            loadAnalytics();
        }, 5000);

        return () => clearInterval(interval);

    }, []);

    const headers = {
        "X-Admin-User-Id": admin?.id
    };

    const actionButton =
        "text-white text-sm font-medium px-4 py-2 rounded-lg transition inline-flex items-center justify-center w-auto min-w-[160px]";

    const tableButton =
        "text-white text-xs font-medium px-3 py-1 rounded-lg transition inline-flex items-center justify-center w-auto min-w-[85px]";

    const loadUsers = async () => {

        try {

            const response = await axios.get(
                `${API_URL}/admin/users`,
                { headers }
            );

            setUsers(response.data);

        } catch (err) {

            setError(
                err?.response?.data?.message ||
                "Unable to load users."
            );
        }
    };

    const buildNotificationText = (log) => {
        if (!log) {
            return null;
        }

        const actionType = (log.action_type || "").toUpperCase();
        const severity = (log.severity_level || "").toLowerCase();

        if (
            actionType.includes("BRUTE_FORCE") ||
            actionType.includes("LOGIN_BLOCKED")
        ) {
            return `🚨 Brute force / blocked login detected from IP ${log.source_ip || "Unknown"}`;
        }

        if (
            actionType.includes("FILE_SCAN") &&
            severity === "warning"
        ) {
            return `⚠️ Suspicious file scan detected: ${log.target_resource || "Unknown file"}`;
        }

        if (actionType.includes("ADMIN_BLOCK_USER")) {
            return `🔴 Admin blocked a user: ${log.target_resource || "Unknown user"}`;
        }

        if (actionType.includes("ADMIN_UNBLOCK_USER")) {
            return `🟢 Admin unblocked a user: ${log.target_resource || "Unknown user"}`;
        }

        if (actionType.includes("LOGIN_FAILED")) {
            return `🟡 Failed login attempt detected from IP ${log.source_ip || "Unknown"}`;
        }

        if (severity === "critical") {
            return `🚨 Critical security event: ${log.action || actionType}`;
        }

        return null;
    };

    const loadAuditLogs = async (silent = false) => {

        try {

            const response = await axios.get(
                `${API_URL}/admin/audit`,
                { headers }
            );

            const logs = response.data || [];

            if (
                silent &&
                logs.length > 0 &&
                lastAuditId !== null
            ) {
                const newLogs = logs.filter((log) =>
                    log.id > lastAuditId
                );

                const newNotifications = newLogs
                    .map((log) => ({
                        id: log.id,
                        text: buildNotificationText(log),
                        timestamp: log.timestamp,
                        severity: log.severity_level
                    }))
                    .filter((notification) => notification.text);

                if (newNotifications.length > 0) {
                    setNotifications((prev) => [
                        ...newNotifications,
                        ...prev
                    ].slice(0, 8));
                }
            }

            if (logs.length > 0) {
                setLastAuditId(logs[0].id);
            }

            setAuditLogs(logs);

        } catch (err) {

            if (!silent) {
                setError(
                    err?.response?.data?.message ||
                    "Unable to load audit logs."
                );
            }
        }
    };

    const loadAnalytics = async () => {

        try {

            const response = await axios.get(
                `${API_URL}/admin/analytics`,
                { headers }
            );

            setAnalytics(response.data);

        } catch (err) {

            console.error(
                "Unable to load analytics",
                err
            );
        }
    };

    const refreshAll = () => {
        loadUsers();
        loadAuditLogs();
        loadAnalytics();
    };

    const blockUser = async (id) => {
        await axios.post(
            `${API_URL}/admin/users/${id}/block`,
            {},
            { headers }
        );

        refreshAll();
    };

    const unblockUser = async (id) => {
        await axios.post(
            `${API_URL}/admin/users/${id}/unblock`,
            {},
            { headers }
        );

        refreshAll();
    };

    const deleteUser = async (id) => {

        if (!confirm("Delete this user permanently?")) {
            return;
        }

        await axios.delete(
            `${API_URL}/admin/users/${id}/delete`,
            { headers }
        );

        refreshAll();
    };

    const downloadCSV = (id) => {
        window.open(
            `${API_URL}/admin/users/${id}/report/csv?admin_id=${admin?.id}`,
            "_blank"
        );
    };

    const downloadPDF = (id) => {
        window.open(
            `${API_URL}/admin/users/${id}/report/pdf?admin_id=${admin?.id}`,
            "_blank"
        );
    };

    const exportAuditCSV = () => {
        window.open(
            `${API_URL}/admin/audit/export/csv?admin_id=${admin?.id}`,
            "_blank"
        );
    };

    const exportLoginCSV = () => {
        window.open(
            `${API_URL}/export/logins`,
            "_blank"
        );
    };

    const exportScanCSV = () => {
        window.open(
            `${API_URL}/export/scans`,
            "_blank"
        );
    };

    const downloadExecutiveReport = () => {
        window.open(
            `${API_URL}/admin/security-report/pdf?admin_id=${admin?.id}`,
            "_blank"
        );
    };

    const clearNotifications = () => {
        setNotifications([]);
    };

    const logout = () => {
        localStorage.removeItem("user");
        localStorage.removeItem("token");
        navigate("/");
    };

    const analyticsCards = [
        {
            title: "Total Users",
            value: analytics.total_users,
            color: "text-cyan-400"
        },
        {
            title: "Total Admins",
            value: analytics.total_admins,
            color: "text-purple-400"
        },
        {
            title: "Blocked Users",
            value: analytics.blocked_users,
            color: "text-red-400"
        },
        {
            title: "Total Scans",
            value: analytics.total_scans,
            color: "text-green-400"
        },
        {
            title: "Threats Detected",
            value: analytics.threats_detected,
            color: "text-yellow-400"
        },
        {
            title: "Login Attempts",
            value: analytics.login_attempts,
            color: "text-blue-400"
        }
    ];

    const barChartData = {
        labels: [
            "Users",
            "Admins",
            "Blocked",
            "Scans",
            "Threats",
            "Logins"
        ],
        datasets: [
            {
                label: "Security Metrics",
                data: [
                    analytics.total_users,
                    analytics.total_admins,
                    analytics.blocked_users,
                    analytics.total_scans,
                    analytics.threats_detected,
                    analytics.login_attempts
                ],
                backgroundColor: [
                    "rgba(34, 211, 238, 0.7)",
                    "rgba(168, 85, 247, 0.7)",
                    "rgba(248, 113, 113, 0.7)",
                    "rgba(34, 197, 94, 0.7)",
                    "rgba(250, 204, 21, 0.7)",
                    "rgba(96, 165, 250, 0.7)"
                ],
                borderWidth: 1
            }
        ]
    };

    const loginChartData = {
        labels: [
            "Successful Logins",
            "Failed Logins",
            "Brute Force Blocks"
        ],
        datasets: [
            {
                label: "Login Security",
                data: [
                    analytics.successful_logins,
                    analytics.failed_logins,
                    analytics.brute_force_blocks
                ],
                backgroundColor: [
                    "rgba(34, 197, 94, 0.75)",
                    "rgba(250, 204, 21, 0.75)",
                    "rgba(248, 113, 113, 0.75)"
                ],
                borderWidth: 1
            }
        ]
    };

    const chartOptions = {
        responsive: true,
        maintainAspectRatio: false,
        plugins: {
            legend: {
                labels: {
                    color: "#cbd5e1"
                }
            }
        },
        scales: {
            x: {
                ticks: {
                    color: "#cbd5e1"
                },
                grid: {
                    color: "rgba(148, 163, 184, 0.15)"
                }
            },
            y: {
                beginAtZero: true,
                ticks: {
                    color: "#cbd5e1",
                    precision: 0
                },
                grid: {
                    color: "rgba(148, 163, 184, 0.15)"
                }
            }
        }
    };

    const doughnutOptions = {
        responsive: true,
        maintainAspectRatio: false,
        plugins: {
            legend: {
                labels: {
                    color: "#cbd5e1"
                }
            }
        }
    };

    return (
        <div className="min-h-screen bg-slate-950 text-white">

            <header className="border-b border-slate-800">
                <div className="max-w-7xl mx-auto px-6 py-4 flex justify-between items-center">

                    <div>
                        <h1 className="text-3xl font-bold text-red-400">
                            CyberShield Admin
                        </h1>

                        <p className="text-slate-400">
                            Security Analytics, User Management & Audit Journal
                        </p>
                    </div>

                    <button
                        onClick={logout}
                        className={`${actionButton} bg-red-600 hover:bg-red-700`}
                    >
                        Logout
                    </button>

                </div>
            </header>

            <main className="max-w-7xl mx-auto p-6">

                {error && (
                    <div className="mb-6 rounded-xl bg-red-500/10 border border-red-500/30 p-4 text-red-400">
                        {error}
                    </div>
                )}

                <div className="mb-8 bg-slate-900 border border-slate-800 rounded-2xl p-6">

                    <div className="flex flex-wrap justify-center md:justify-between items-center gap-4 mb-4">
                        <div>
                            <h2 className="text-xl font-semibold">
                                Real-Time Security Center
                            </h2>

                            <p className="text-slate-400 text-sm">
                                Auto-refreshes every 5 seconds and highlights new critical events.
                            </p>
                        </div>

                        <div className="flex flex-wrap justify-center md:justify-end gap-2">
                            <button
                                onClick={refreshAll}
                                className={`${actionButton} bg-cyan-600 hover:bg-cyan-700`}
                            >
                                Refresh Now
                            </button>

                            <button
                                onClick={clearNotifications}
                                className={`${actionButton} bg-slate-700 hover:bg-slate-600`}
                            >
                                Clear Notifications
                            </button>

                            <button
                                onClick={downloadExecutiveReport}
                                className={`${actionButton} bg-green-600 hover:bg-green-700`}
                            >
                                Executive Security Report
                            </button>
                        </div>
                    </div>

                    <div className="grid md:grid-cols-5 gap-4 mb-5">
                        {[
                            ["Database", "Healthy"],
                            ["Audit Service", "Active"],
                            ["Email Alerts", "Enabled"],
                            ["VirusTotal", "Connected"],
                            ["Brute Force Protection", "Active"]
                        ].map(([title, status]) => (
                            <div
                                key={title}
                                className="bg-slate-800 rounded-xl p-4"
                            >
                                <p className="text-slate-400 text-sm text-left">
                                    {title}
                                </p>
                                <p className="text-green-400 font-bold mt-1">
                                    {status}
                                </p>
                            </div>
                        ))}
                    </div>

                    <div className="space-y-3">
                        {notifications.length > 0 ? (
                            notifications.map((notification) => (
                                <div
                                    key={notification.id}
                                    className={
                                        notification.severity === "critical"
                                            ? "rounded-xl bg-red-500/10 border border-red-500/30 p-3 text-red-300"
                                            : "rounded-xl bg-yellow-500/10 border border-yellow-500/30 p-3 text-yellow-300"
                                    }
                                >
                                    <p className="font-semibold text-left">
                                        {notification.text}
                                    </p>

                                    <p className="text-xs text-slate-400 mt-1 text-left">
                                        {notification.timestamp}
                                    </p>
                                </div>
                            ))
                        ) : (
                            <div className="rounded-xl bg-slate-800 p-4 text-slate-300">
                                No new real-time security notifications.
                            </div>
                        )}
                    </div>

                </div>

                <div className="mb-8">

                    <div className="flex flex-wrap justify-center md:justify-between items-center gap-4 mb-4">
                        <div>
                            <h2 className="text-xl font-semibold">
                                Security Analytics Dashboard
                            </h2>

                            <p className="text-slate-400 text-sm">
                                Enterprise overview for users, scans, login attempts and detected threats.
                            </p>
                        </div>

                        <button
                            onClick={refreshAll}
                            className={`${actionButton} bg-cyan-600 hover:bg-cyan-700`}
                        >
                            Refresh Analytics
                        </button>
                    </div>

                    <div className="grid sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-6 gap-4">
                        {analyticsCards.map((card) => (
                            <div
                                key={card.title}
                                className="bg-slate-900 border border-slate-800 rounded-2xl p-5"
                            >
                                <p className="text-slate-400 text-sm text-left">
                                    {card.title}
                                </p>

                                <p className={`text-3xl font-bold mt-2 ${card.color}`}>
                                    {card.value ?? 0}
                                </p>
                            </div>
                        ))}
                    </div>

                    <div className="grid lg:grid-cols-2 gap-6 mt-6">

                        <div className="bg-slate-900 border border-slate-800 rounded-2xl p-6">
                            <h3 className="text-lg font-semibold mb-4">
                                Security Overview
                            </h3>

                            <div className="h-80">
                                <Bar
                                    data={barChartData}
                                    options={chartOptions}
                                />
                            </div>
                        </div>

                        <div className="bg-slate-900 border border-slate-800 rounded-2xl p-6">
                            <h3 className="text-lg font-semibold mb-4">
                                Login Security Status
                            </h3>

                            <div className="h-80">
                                <Doughnut
                                    data={loginChartData}
                                    options={doughnutOptions}
                                />
                            </div>
                        </div>

                    </div>

                </div>

                <div className="bg-slate-900 border border-slate-800 rounded-2xl p-6">

                    <h2 className="text-xl font-semibold mb-4">
                        Registered Users
                    </h2>

                    <div className="overflow-x-auto">

                        <table className="w-full text-sm">

                            <thead>
                                <tr className="border-b border-slate-700">
                                    <th className="text-left py-3">ID</th>
                                    <th className="text-left py-3">Name</th>
                                    <th className="text-left py-3">Email</th>
                                    <th className="text-left py-3">Role</th>
                                    <th className="text-left py-3">Blocked</th>
                                    <th className="text-left py-3">Logins</th>
                                    <th className="text-left py-3">Scans</th>
                                    <th className="text-left py-3">Suspicious</th>
                                    <th className="text-left py-3">Password</th>
                                    <th className="text-left py-3">Actions</th>
                                </tr>
                            </thead>

                            <tbody>
                                {users.map((user) => (
                                    <tr
                                        key={user.id}
                                        className="border-b border-slate-800"
                                    >
                                        <td className="py-3">{user.id}</td>
                                        <td className="py-3">{user.username}</td>
                                        <td className="py-3">{user.email}</td>
                                        <td className="py-3">{user.role}</td>
                                        <td className="py-3">
                                            {user.is_blocked ? "Yes" : "No"}
                                        </td>
                                        <td className="py-3">{user.login_count}</td>
                                        <td className="py-3">{user.scan_count}</td>
                                        <td className="py-3">{user.suspicious_count}</td>

                                        <td className="py-3 text-xs text-slate-400">
                                            {user.password_hash_preview}
                                        </td>

                                        <td className="py-3">
                                            <div className="flex flex-wrap justify-center gap-2">

                                                {user.is_blocked ? (
                                                    <button
                                                        onClick={() => unblockUser(user.id)}
                                                        className={`${tableButton} bg-green-600 hover:bg-green-700`}
                                                    >
                                                        Unblock
                                                    </button>
                                                ) : (
                                                    <button
                                                        onClick={() => blockUser(user.id)}
                                                        className={`${tableButton} bg-yellow-600 hover:bg-yellow-700`}
                                                    >
                                                        Block
                                                    </button>
                                                )}

                                                <button
                                                    onClick={() => deleteUser(user.id)}
                                                    className={`${tableButton} bg-red-600 hover:bg-red-700`}
                                                >
                                                    Delete
                                                </button>

                                                <button
                                                    onClick={() => downloadCSV(user.id)}
                                                    className={`${tableButton} bg-green-600 hover:bg-green-700`}
                                                >
                                                    CSV
                                                </button>

                                                <button
                                                    onClick={() => downloadPDF(user.id)}
                                                    className={`${tableButton} bg-green-600 hover:bg-green-700`}
                                                >
                                                    PDF
                                                </button>

                                            </div>
                                        </td>
                                    </tr>
                                ))}
                            </tbody>

                        </table>

                    </div>

                </div>

                <div className="mt-8 bg-slate-900 border border-slate-800 rounded-2xl p-6">

                    <div className="flex flex-wrap justify-center md:justify-between items-center gap-4 mb-4">

                        <div>
                            <h2 className="text-xl font-semibold">
                                Audit Journal
                            </h2>

                            <p className="text-slate-400 text-sm">
                                System activity, login attempts, scans, admin actions and IP geolocation.
                            </p>
                        </div>

                        <div className="flex flex-wrap justify-center md:justify-end gap-2">

                            <button
                                onClick={loadAuditLogs}
                                className={`${actionButton} bg-cyan-600 hover:bg-cyan-700`}
                            >
                                Refresh Audit
                            </button>

                            <button
                                onClick={exportAuditCSV}
                                className={`${actionButton} bg-green-600 hover:bg-green-700`}
                            >
                                Export Audit CSV
                            </button>

                            <button
                                onClick={exportLoginCSV}
                                className={`${actionButton} bg-green-600 hover:bg-green-700`}
                            >
                                Export Logins CSV
                            </button>

                            <button
                                onClick={exportScanCSV}
                                className={`${actionButton} bg-green-600 hover:bg-green-700`}
                            >
                                Export Scans CSV
                            </button>

                            <button
                                onClick={downloadExecutiveReport}
                                className={`${actionButton} bg-green-600 hover:bg-green-700`}
                            >
                                Executive PDF
                            </button>

                        </div>

                    </div>

                    <div className="overflow-x-auto">

                        <table className="w-full text-sm">

                            <thead>
                                <tr className="border-b border-slate-700">
                                    <th className="text-left py-3">Date</th>
                                    <th className="text-left py-3">User ID</th>
                                    <th className="text-left py-3">Role</th>
                                    <th className="text-left py-3">Action Type</th>
                                    <th className="text-left py-3">Action</th>
                                    <th className="text-left py-3">Target</th>
                                    <th className="text-left py-3">IP</th>
                                    <th className="text-left py-3">Country</th>
                                    <th className="text-left py-3">City</th>
                                    <th className="text-left py-3">ISP</th>
                                    <th className="text-left py-3">Coordinates</th>
                                    <th className="text-left py-3">Severity</th>
                                </tr>
                            </thead>

                            <tbody>
                                {auditLogs.map((log) => (
                                    <tr
                                        key={log.id}
                                        className="border-b border-slate-800"
                                    >
                                        <td className="py-3 text-slate-300">
                                            {log.timestamp}
                                        </td>

                                        <td className="py-3">
                                            {log.user_id || "Guest"}
                                        </td>

                                        <td className="py-3">
                                            {log.role}
                                        </td>

                                        <td className="py-3 text-cyan-300">
                                            {log.action_type}
                                        </td>

                                        <td className="py-3 max-w-md">
                                            {log.action}
                                        </td>

                                        <td className="py-3">
                                            {log.target_resource || "-"}
                                        </td>

                                        <td className="py-3">
                                            {log.source_ip || "-"}
                                        </td>

                                        <td className="py-3">
                                            {log.country || "Local / Unknown"}
                                        </td>

                                        <td className="py-3">
                                            {log.city || "Local / Unknown"}
                                        </td>

                                        <td className="py-3">
                                            {log.isp || "Local / Unknown"}
                                        </td>

                                        <td className="py-3">
                                            {log.latitude && log.longitude
                                                ? `${log.latitude}, ${log.longitude}`
                                                : "-"}
                                        </td>

                                        <td className="py-3">
                                            <span
                                                className={
                                                    log.severity_level === "critical"
                                                        ? "text-red-400 font-bold"
                                                        : log.severity_level === "warning"
                                                            ? "text-yellow-400 font-bold"
                                                            : "text-green-400 font-bold"
                                                }
                                            >
                                                {log.severity_level}
                                            </span>
                                        </td>
                                    </tr>
                                ))}

                                {auditLogs.length === 0 && (
                                    <tr>
                                        <td
                                            colSpan="12"
                                            className="py-6 text-center text-slate-400"
                                        >
                                            No audit logs available.
                                        </td>
                                    </tr>
                                )}
                            </tbody>

                        </table>

                    </div>

                </div>

            </main>

            <AssistantBubble
                user={admin}
                stats={{
                    threats_blocked: analytics.threats_detected,
                    files_scanned: analytics.total_scans,
                    security_score: analytics.threats_detected > 0
                        ? Math.max(0, 100 - analytics.threats_detected * 2)
                        : 100
                }}
                scans={[]}
                users={users}
                analytics={analytics}
                auditLogs={auditLogs}
                activity={auditLogs.map((log) =>
                    `${log.action_type}: ${log.action}`
                )}
                isAdmin={true}
            />

        </div>
    );
}
