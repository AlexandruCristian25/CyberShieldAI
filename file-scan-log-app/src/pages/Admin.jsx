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

    const [openSections, setOpenSections] = useState({
        executive: true,
        behavior: false,
        managerapp: false,
        system: false,
        analytics: false,
        users: false,
        audit: false
    });

    const [threatIntel, setThreatIntel] = useState({
        top_suspicious_users: [],
        top_suspicious_ips: []
    });

    const [managerIntel, setManagerIntel] = useState({
        overview: {
            total_events: 0,
            login_success: 0,
            login_failed: 0,
            projects_created: 0,
            projects_updated: 0,
            projects_deleted: 0,
            suspicious_events: 0
        },
        top_active_users: [],
        top_suspicious_users: [],
        most_deleted_projects: [],
        event_distribution: [],
        daily_activity: [],
        latest_events: []
    });

    const [behaviorAnalysis, setBehaviorAnalysis] = useState({
        overview: {
            total_events: 0,
            monitored_users: 0,
            suspicious_events: 0,
            deleted_projects: 0,
            failed_logins: 0,
            highest_threat_score: 0,
            global_risk_level: "Low"
        },
        analysis_model: {
            name: "CyberShield AI Behavioral Rules Engine",
            version: "1.0",
            rules: []
        },
        users: [],
        timeline: []
    });

    const [executiveDashboard, setExecutiveDashboard] = useState({
        protected_application: "ManagerApp",
        platform: "CyberShield AI Enterprise Security Platform",
        overall_security_score: 100,
        security_level: "Excellent",
        threat_level: "Low",
        summary: {
            total_users: 0,
            managerapp_users: 0,
            total_scans: 0,
            threats_detected: 0,
            critical_events: 0,
            suspicious_events: 0,
            failed_logins: 0,
            managerapp_events: 0,
            managerapp_project_deletions: 0
        },
        executive_recommendation: "Security posture is strong. Continue monitoring.",
        soc_timeline: []
    });


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
        loadThreatIntelligence();
        loadManagerAppIntelligence();
        loadBehaviorAnalysis();
        loadExecutiveDashboard();

        const interval = setInterval(() => {
            loadUsers();
            loadAuditLogs(true);
            loadAnalytics();
            loadThreatIntelligence();
            loadManagerAppIntelligence();
            loadBehaviorAnalysis();
            loadExecutiveDashboard();
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

    const toggleSection = (sectionName) => {
        setOpenSections((prev) => ({
            ...prev,
            [sectionName]: !prev[sectionName]
        }));
    };

    const SectionHeader = ({ id, title, subtitle }) => (
        <button
            type="button"
            onClick={() => toggleSection(id)}
            className="w-full mb-4 bg-slate-900 border border-slate-800 rounded-2xl px-6 py-5 flex flex-wrap items-center justify-between gap-3 text-left hover:border-cyan-500/50 transition"
        >
            <div>
                <h2 className="text-xl font-semibold">
                    {title}
                </h2>

                <p className="text-slate-400 text-sm mt-1">
                    {subtitle}
                </p>
            </div>

            <span className="rounded-full bg-slate-800 border border-slate-700 px-4 py-2 text-sm text-cyan-300">
                {openSections[id] ? "▲ Close" : "▼ Open"}
            </span>
        </button>
    );

    const getRiskBadgeClass = (riskLevel) => {
        if (riskLevel === "Critical") {
            return "bg-red-600/20 text-red-200 border border-red-500/40";
        }

        if (riskLevel === "High") {
            return "bg-red-500/10 text-red-300 border border-red-500/30";
        }

        if (riskLevel === "Medium") {
            return "bg-yellow-500/10 text-yellow-300 border border-yellow-500/30";
        }

        return "bg-green-500/10 text-green-300 border border-green-500/30";
    };

    const getRiskBarClass = (riskLevel) => {
        if (riskLevel === "Critical") {
            return "bg-red-600";
        }

        if (riskLevel === "High") {
            return "bg-red-500";
        }

        if (riskLevel === "Medium") {
            return "bg-yellow-500";
        }

        return "bg-green-500";
    };

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

    
    const loadThreatIntelligence = async () => {
        try {
            const response = await axios.get(
                `${API_URL}/admin/threat-intelligence`,
                { headers }
            );

            setThreatIntel({
                top_suspicious_users:
                    response.data.top_suspicious_users || [],
                top_suspicious_ips:
                    response.data.top_suspicious_ips || []
            });

        } catch (err) {
            console.error("Unable to load threat intelligence", err);
        }
    };

    const loadManagerAppIntelligence = async () => {
        try {
            const response = await axios.get(
                `${API_URL}/admin/managerapp-intelligence`,
                { headers }
            );

            setManagerIntel({
                overview: response.data.overview || {
                    total_events: 0,
                    login_success: 0,
                    login_failed: 0,
                    projects_created: 0,
                    projects_updated: 0,
                    projects_deleted: 0,
                    suspicious_events: 0
                },
                top_active_users: response.data.top_active_users || [],
                top_suspicious_users: response.data.top_suspicious_users || [],
                most_deleted_projects: response.data.most_deleted_projects || [],
                event_distribution: response.data.event_distribution || [],
                daily_activity: response.data.daily_activity || [],
                latest_events: response.data.latest_events || []
            });

        } catch (err) {
            console.error("Unable to load ManagerApp intelligence", err);
        }
    };

    const loadBehaviorAnalysis = async () => {
        try {
            const response = await axios.get(
                `${API_URL}/admin/behavior-analysis`,
                { headers }
            );

            setBehaviorAnalysis({
                overview: response.data.overview || {
                    total_events: 0,
                    monitored_users: 0,
                    suspicious_events: 0,
                    deleted_projects: 0,
                    failed_logins: 0,
                    highest_threat_score: 0,
                    global_risk_level: "Low"
                },
                analysis_model: response.data.analysis_model || {
                    name: "CyberShield AI Behavioral Rules Engine",
                    version: "1.0",
                    rules: []
                },
                users: response.data.users || [],
                timeline: response.data.timeline || []
            });

        } catch (err) {
            console.error("Unable to load AI behavioral analysis", err);
        }
    };

    const loadExecutiveDashboard = async () => {
        try {
            const response = await axios.get(
                `${API_URL}/admin/executive-dashboard`,
                { headers }
            );

            setExecutiveDashboard({
                protected_application: response.data.protected_application || "ManagerApp",
                platform: response.data.platform || "CyberShield AI Enterprise Security Platform",
                overall_security_score: response.data.overall_security_score ?? 100,
                security_level: response.data.security_level || "Excellent",
                threat_level: response.data.threat_level || "Low",
                summary: response.data.summary || {
                    total_users: 0,
                    managerapp_users: 0,
                    total_scans: 0,
                    threats_detected: 0,
                    critical_events: 0,
                    suspicious_events: 0,
                    failed_logins: 0,
                    managerapp_events: 0,
                    managerapp_project_deletions: 0
                },
                executive_recommendation:
                    response.data.executive_recommendation ||
                    "Security posture is strong. Continue monitoring.",
                soc_timeline: response.data.soc_timeline || []
            });

        } catch (err) {
            console.error("Unable to load executive dashboard", err);
        }
    };


    const refreshAll = () => {
        loadUsers();
        loadAuditLogs();
        loadAnalytics();
        loadThreatIntelligence();
        loadManagerAppIntelligence();
        loadBehaviorAnalysis();
        loadExecutiveDashboard();
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

    const managerEventChartData = {
        labels: managerIntel.event_distribution.map((item) =>
            item.event_type
        ),
        datasets: [
            {
                label: "ManagerApp Events",
                data: managerIntel.event_distribution.map((item) =>
                    item.count
                ),
                backgroundColor: [
                    "rgba(34, 211, 238, 0.7)",
                    "rgba(168, 85, 247, 0.7)",
                    "rgba(34, 197, 94, 0.7)",
                    "rgba(250, 204, 21, 0.7)",
                    "rgba(248, 113, 113, 0.7)",
                    "rgba(96, 165, 250, 0.7)",
                    "rgba(244, 114, 182, 0.7)"
                ],
                borderWidth: 1
            }
        ]
    };

    const managerDailyChartData = {
        labels: managerIntel.daily_activity.map((item) =>
            item.date
        ),
        datasets: [
            {
                label: "Daily ManagerApp Activity",
                data: managerIntel.daily_activity.map((item) =>
                    item.count
                ),
                backgroundColor: "rgba(34, 211, 238, 0.7)",
                borderWidth: 1
            }
        ]
    };

    const behaviorRiskChartData = {
        labels: behaviorAnalysis.users.map((user) =>
            user.username
        ),
        datasets: [
            {
                label: "AI Threat Score",
                data: behaviorAnalysis.users.map((user) =>
                    user.threat_score
                ),
                backgroundColor: "rgba(248, 113, 113, 0.75)",
                borderWidth: 1
            }
        ]
    };

    const executiveScoreChartData = {
        labels: [
            "Security Score",
            "Remaining Risk"
        ],
        datasets: [
            {
                label: "Executive Security Score",
                data: [
                    executiveDashboard.overall_security_score,
                    Math.max(0, 100 - executiveDashboard.overall_security_score)
                ],
                backgroundColor: [
                    "rgba(34, 197, 94, 0.75)",
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
                            Enterprise SOC Dashboard, AI Behavioral Analysis & ManagerApp Protection
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


                <SectionHeader
                    id="executive"
                    title="🏆 Executive Dashboard"
                    subtitle="Management-level SOC overview, security score and timeline."
                />

                {openSections.executive && (
                    <div className="mb-8">
                <div className="mb-10 bg-slate-900 border border-slate-800 rounded-2xl p-6">

                    <div className="flex flex-wrap justify-center md:justify-between items-center gap-4 mb-5">
                        <div>
                            <h2 className="text-xl font-semibold">
                                🏆 Executive Dashboard
                            </h2>

                            <p className="text-slate-400 text-sm">
                                Management-level security posture and SOC overview for {executiveDashboard.protected_application}.
                            </p>
                        </div>

                        <button
                            onClick={loadExecutiveDashboard}
                            className={`${actionButton} bg-emerald-600 hover:bg-emerald-700`}
                        >
                            Refresh Executive View
                        </button>
                    </div>

                    <div className="grid lg:grid-cols-3 gap-6 mb-6">

                        <div className="bg-slate-950/50 border border-slate-800 rounded-2xl p-6">
                            <p className="text-slate-400 text-sm text-left">
                                Overall Security Score
                            </p>

                            <p className={
                                executiveDashboard.overall_security_score >= 75
                                    ? "text-5xl font-bold text-green-400 mt-3"
                                    : executiveDashboard.overall_security_score >= 55
                                        ? "text-5xl font-bold text-yellow-400 mt-3"
                                        : "text-5xl font-bold text-red-400 mt-3"
                            }>
                                {executiveDashboard.overall_security_score}/100
                            </p>

                            <div className="h-3 bg-slate-700 rounded-full overflow-hidden mt-5">
                                <div
                                    className={
                                        executiveDashboard.overall_security_score >= 75
                                            ? "h-full bg-green-500"
                                            : executiveDashboard.overall_security_score >= 55
                                                ? "h-full bg-yellow-500"
                                                : "h-full bg-red-500"
                                    }
                                    style={{
                                        width: `${executiveDashboard.overall_security_score}%`
                                    }}
                                ></div>
                            </div>

                            <p className="text-slate-300 mt-4 text-left">
                                Security Level:{" "}
                                <span className="font-bold">
                                    {executiveDashboard.security_level}
                                </span>
                            </p>

                            <p className="text-slate-300 mt-1 text-left">
                                Threat Level:{" "}
                                <span className={
                                    executiveDashboard.threat_level === "Low"
                                        ? "text-green-400 font-bold"
                                        : executiveDashboard.threat_level === "Medium"
                                            ? "text-yellow-400 font-bold"
                                            : "text-red-400 font-bold"
                                }>
                                    {executiveDashboard.threat_level}
                                </span>
                            </p>
                        </div>

                        <div className="bg-slate-950/50 border border-slate-800 rounded-2xl p-6">
                            <h3 className="font-semibold mb-4">
                                Executive Score Distribution
                            </h3>

                            <div className="h-72">
                                <Doughnut
                                    data={executiveScoreChartData}
                                    options={doughnutOptions}
                                />
                            </div>
                        </div>

                        <div className="bg-slate-950/50 border border-slate-800 rounded-2xl p-6">
                            <h3 className="font-semibold mb-4 text-emerald-400">
                                AI Executive Recommendation
                            </h3>

                            <p className="text-slate-300 text-left leading-relaxed">
                                {executiveDashboard.executive_recommendation}
                            </p>

                            <div className="mt-5 bg-slate-800 rounded-xl p-4 border border-slate-700">
                                <p className="text-xs text-slate-400 text-left">
                                    Protected Application
                                </p>

                                <p className="font-semibold text-white text-left mt-1">
                                    {executiveDashboard.protected_application}
                                </p>

                                <p className="text-xs text-slate-400 text-left mt-3">
                                    Security Platform
                                </p>

                                <p className="font-semibold text-white text-left mt-1">
                                    {executiveDashboard.platform}
                                </p>
                            </div>
                        </div>

                    </div>

                    <div className="grid sm:grid-cols-2 lg:grid-cols-4 xl:grid-cols-9 gap-4 mb-6">
                        {[
                            ["Total Users", executiveDashboard.summary.total_users, "text-cyan-400"],
                            ["ManagerApp Users", executiveDashboard.summary.managerapp_users, "text-purple-400"],
                            ["Total Scans", executiveDashboard.summary.total_scans, "text-green-400"],
                            ["Threats", executiveDashboard.summary.threats_detected, "text-yellow-400"],
                            ["Critical", executiveDashboard.summary.critical_events, "text-red-400"],
                            ["Suspicious", executiveDashboard.summary.suspicious_events, "text-orange-400"],
                            ["Failed Logins", executiveDashboard.summary.failed_logins, "text-yellow-300"],
                            ["App Events", executiveDashboard.summary.managerapp_events, "text-blue-400"],
                            ["Deletions", executiveDashboard.summary.managerapp_project_deletions, "text-red-300"]
                        ].map(([title, value, color]) => (
                            <div
                                key={title}
                                className="bg-slate-950/50 border border-slate-800 rounded-2xl p-4"
                            >
                                <p className="text-slate-400 text-xs text-left">
                                    {title}
                                </p>

                                <p className={`text-2xl font-bold mt-2 ${color}`}>
                                    {value ?? 0}
                                </p>
                            </div>
                        ))}
                    </div>

                    <div className="bg-slate-950/50 border border-slate-800 rounded-2xl p-5">
                        <h3 className="font-semibold mb-5 text-cyan-400">
                            SOC Timeline
                        </h3>

                        <div className="relative border-l border-cyan-500/40 ml-4 space-y-5 max-h-[520px] overflow-y-auto pr-2">
                            {executiveDashboard.soc_timeline.length === 0 && (
                                <div className="ml-6 rounded-xl bg-slate-800 p-4 text-slate-400 text-sm">
                                    No SOC timeline events available yet.
                                </div>
                            )}

                            {executiveDashboard.soc_timeline.map((event) => (
                                <div
                                    key={event.id}
                                    className="relative ml-6 bg-slate-800 rounded-xl p-4 border border-slate-700"
                                >
                                    <div className="absolute -left-[33px] top-5 w-4 h-4 rounded-full bg-cyan-400 border-4 border-slate-950"></div>

                                    <div className="flex flex-wrap justify-between gap-3 mb-2">
                                        <div>
                                            <p className="font-bold text-cyan-300 text-left">
                                                {event.time} — {event.event_type}
                                            </p>

                                            <p className="text-xs text-slate-400 text-left">
                                                {event.username} | {event.email} | {event.role}
                                            </p>
                                        </div>

                                        <span
                                            className={
                                                event.severity_level === "critical"
                                                    ? "text-red-400 font-bold"
                                                    : event.severity_level === "warning"
                                                        ? "text-yellow-400 font-bold"
                                                        : "text-green-400 font-bold"
                                            }
                                        >
                                            {event.severity_level}
                                        </span>
                                    </div>

                                    <p className="text-sm text-slate-200 text-left">
                                        {event.action}
                                    </p>

                                    <div className="grid md:grid-cols-4 gap-2 text-xs text-slate-400 mt-3">
                                        <div className="bg-slate-900 rounded-lg p-2">
                                            IP: {event.source_ip || "-"}
                                        </div>

                                        <div className="bg-slate-900 rounded-lg p-2">
                                            Location: {event.city || "Unknown"}, {event.country || "Unknown"}
                                        </div>

                                        <div className="bg-slate-900 rounded-lg p-2">
                                            ISP: {event.isp || "Unknown"}
                                        </div>

                                        <div className="bg-slate-900 rounded-lg p-2">
                                            Device: {event.device_type || "Unknown"}
                                        </div>

                                        <div className="bg-slate-900 rounded-lg p-2">
                                            Browser: {event.browser || "Unknown"}
                                        </div>

                                        <div className="bg-slate-900 rounded-lg p-2">
                                            OS: {event.operating_system || "Unknown"}
                                        </div>

                                        <div className="bg-slate-900 rounded-lg p-2">
                                            Target: {event.target_resource || "-"}
                                        </div>

                                        <div className="bg-slate-900 rounded-lg p-2">
                                            Timestamp: {event.timestamp}
                                        </div>
                                    </div>
                                </div>
                            ))}
                        </div>
                    </div>

                </div>
                    </div>
                )}

                <SectionHeader
                    id="behavior"
                    title="🧠 AI Behavioral Analysis"
                    subtitle="AI risk scoring, abnormal behavior and insider-threat patterns."
                />

                {openSections.behavior && (
                    <div className="mb-8">
                <div className="mb-10 bg-slate-900 border border-slate-800 rounded-2xl p-6">

                    <div className="flex flex-wrap justify-center md:justify-between items-center gap-4 mb-5">
                        <div>
                            <h2 className="text-xl font-semibold">
                                🧠 AI Behavioral Analysis
                            </h2>

                            <p className="text-slate-400 text-sm">
                                Behavioral engine for insider-threat detection, abnormal activity and ManagerApp risk scoring.
                            </p>
                        </div>

                        <button
                            onClick={loadBehaviorAnalysis}
                            className={`${actionButton} bg-fuchsia-600 hover:bg-fuchsia-700`}
                        >
                            Refresh AI Analysis
                        </button>
                    </div>

                    <div className="grid sm:grid-cols-2 lg:grid-cols-4 xl:grid-cols-7 gap-4 mb-6">
                        {[
                            ["Total Events", behaviorAnalysis.overview.total_events, "text-cyan-400"],
                            ["Monitored Users", behaviorAnalysis.overview.monitored_users, "text-purple-400"],
                            ["Suspicious Events", behaviorAnalysis.overview.suspicious_events, "text-yellow-400"],
                            ["Deleted Projects", behaviorAnalysis.overview.deleted_projects, "text-red-400"],
                            ["Failed Logins", behaviorAnalysis.overview.failed_logins, "text-orange-400"],
                            ["Highest Score", behaviorAnalysis.overview.highest_threat_score, "text-red-300"],
                            ["Global Risk", behaviorAnalysis.overview.global_risk_level, "text-fuchsia-300"]
                        ].map(([title, value, color]) => (
                            <div
                                key={title}
                                className="bg-slate-950/50 border border-slate-800 rounded-2xl p-4"
                            >
                                <p className="text-slate-400 text-xs text-left">
                                    {title}
                                </p>

                                <p className={`text-2xl font-bold mt-2 ${color}`}>
                                    {value ?? 0}
                                </p>
                            </div>
                        ))}
                    </div>

                    <div className="grid lg:grid-cols-2 gap-6 mb-6">

                        <div className="bg-slate-950/50 border border-slate-800 rounded-2xl p-5">
                            <h3 className="font-semibold mb-4 text-fuchsia-400">
                                AI Model
                            </h3>

                            <div className="bg-slate-800 rounded-xl p-4 border border-slate-700 mb-4">
                                <p className="font-semibold text-white text-left">
                                    {behaviorAnalysis.analysis_model.name}
                                </p>

                                <p className="text-xs text-slate-400 text-left mt-1">
                                    Version: {behaviorAnalysis.analysis_model.version}
                                </p>
                            </div>

                            <div className="space-y-2">
                                {(behaviorAnalysis.analysis_model.rules || []).map((rule) => (
                                    <div
                                        key={rule}
                                        className="bg-slate-800 rounded-lg p-3 text-sm text-slate-300 text-left"
                                    >
                                        ✓ {rule}
                                    </div>
                                ))}
                            </div>
                        </div>

                        <div className="bg-slate-950/50 border border-slate-800 rounded-2xl p-5">
                            <h3 className="font-semibold mb-4">
                                AI Threat Score by User
                            </h3>

                            <div className="h-80">
                                <Bar
                                    data={behaviorRiskChartData}
                                    options={chartOptions}
                                />
                            </div>
                        </div>

                    </div>

                    <div className="grid lg:grid-cols-2 gap-6 mb-6">

                        <div className="bg-slate-950/50 border border-slate-800 rounded-2xl p-5">
                            <h3 className="font-semibold mb-4 text-red-400">
                                Top Behavioral Risk Users
                            </h3>

                            <div className="space-y-4">
                                {behaviorAnalysis.users.length === 0 && (
                                    <div className="rounded-xl bg-slate-800 p-4 text-slate-400 text-sm">
                                        No abnormal behavior detected yet.
                                    </div>
                                )}

                                {behaviorAnalysis.users.map((user, index) => (
                                    <div
                                        key={`${user.email}-${index}`}
                                        className="bg-slate-800 rounded-xl p-4 border border-slate-700"
                                    >
                                        <div className="flex flex-wrap items-center justify-between gap-3 mb-3">
                                            <div>
                                                <p className="font-semibold text-white text-left">
                                                    {user.username}
                                                </p>

                                                <p className="text-xs text-slate-400 text-left">
                                                    {user.email} | {user.role}
                                                </p>
                                            </div>

                                            <span
                                                className={`text-xs font-bold px-3 py-1 rounded-full ${getRiskBadgeClass(user.risk_level)}`}
                                            >
                                                {user.risk_level} Risk
                                            </span>
                                        </div>

                                        <div className="mb-3">
                                            <div className="flex justify-between text-xs mb-1">
                                                <span className="text-slate-400">
                                                    AI Threat Score
                                                </span>

                                                <span className="font-bold text-red-300">
                                                    {user.threat_score}/100
                                                </span>
                                            </div>

                                            <div className="h-2 bg-slate-700 rounded-full overflow-hidden">
                                                <div
                                                    className={`h-full ${getRiskBarClass(user.risk_level)}`}
                                                    style={{
                                                        width: `${user.threat_score}%`
                                                    }}
                                                ></div>
                                            </div>
                                        </div>

                                        <div className="grid sm:grid-cols-3 gap-2 text-xs text-slate-300 mb-3">
                                            <div className="bg-slate-900 rounded-lg p-2">
                                                Confidence: {user.confidence}%
                                            </div>

                                            <div className="bg-slate-900 rounded-lg p-2">
                                                Events: {user.total_events}
                                            </div>

                                            <div className="bg-slate-900 rounded-lg p-2">
                                                Unique IPs: {user.unique_ips}
                                            </div>
                                        </div>

                                        <div className="space-y-2">
                                            {(user.behaviors || []).map((behavior) => (
                                                <div
                                                    key={`${user.email}-${behavior.type}`}
                                                    className={
                                                        behavior.severity === "High"
                                                            ? "bg-red-500/10 border border-red-500/30 rounded-lg p-3"
                                                            : "bg-yellow-500/10 border border-yellow-500/30 rounded-lg p-3"
                                                    }
                                                >
                                                    <p className="font-semibold text-left text-sm">
                                                        {behavior.type}
                                                    </p>

                                                    <p className="text-xs text-slate-300 mt-1 text-left">
                                                        {behavior.description}
                                                    </p>
                                                </div>
                                            ))}
                                        </div>

                                        <div className="mt-3 bg-slate-900 rounded-lg p-3">
                                            <p className="text-xs text-slate-400 text-left">
                                                AI Recommendation
                                            </p>

                                            <p className="text-sm text-slate-200 mt-1 text-left">
                                                {user.recommendation}
                                            </p>
                                        </div>

                                        <p className="text-xs text-slate-400 mt-3 text-left">
                                            First Activity: {user.first_activity} | Last Activity: {user.last_activity}
                                        </p>
                                    </div>
                                ))}
                            </div>
                        </div>

                        <div className="bg-slate-950/50 border border-slate-800 rounded-2xl p-5">
                            <h3 className="font-semibold mb-4 text-purple-400">
                                Behavioral Timeline
                            </h3>

                            <div className="space-y-3 max-h-[760px] overflow-y-auto pr-2">
                                {behaviorAnalysis.timeline.length === 0 && (
                                    <div className="rounded-xl bg-slate-800 p-4 text-slate-400 text-sm">
                                        No behavioral timeline events available yet.
                                    </div>
                                )}

                                {behaviorAnalysis.timeline.map((event) => (
                                    <div
                                        key={event.id}
                                        className="bg-slate-800 rounded-xl p-4 border border-slate-700"
                                    >
                                        <div className="flex flex-wrap justify-between gap-3 mb-2">
                                            <div>
                                                <p className="font-semibold text-cyan-300 text-left">
                                                    {event.event_type}
                                                </p>

                                                <p className="text-xs text-slate-400 text-left">
                                                    {event.timestamp} | {event.username} | {event.email}
                                                </p>
                                            </div>

                                            <span
                                                className={
                                                    event.severity_level === "critical"
                                                        ? "text-red-400 font-bold"
                                                        : event.severity_level === "warning"
                                                            ? "text-yellow-400 font-bold"
                                                            : "text-green-400 font-bold"
                                                }
                                            >
                                                {event.severity_level}
                                            </span>
                                        </div>

                                        <p className="text-sm text-slate-200 text-left">
                                            {event.action}
                                        </p>

                                        <div className="grid md:grid-cols-3 gap-2 text-xs text-slate-400 mt-3">
                                            <div className="bg-slate-900 rounded-lg p-2">
                                                Target: {event.target_resource || "-"}
                                            </div>

                                            <div className="bg-slate-900 rounded-lg p-2">
                                                IP: {event.source_ip || "-"}
                                            </div>

                                            <div className="bg-slate-900 rounded-lg p-2">
                                                Location: {event.city || "Unknown"}, {event.country || "Unknown"}
                                            </div>
                                        </div>
                                    </div>
                                ))}
                            </div>
                        </div>

                    </div>

                </div>
                    </div>
                )}

                <SectionHeader
                    id="managerapp"
                    title="📊 ManagerApp Intelligence"
                    subtitle="ManagerApp users, project actions and operational risk."
                />

                {openSections.managerapp && (
                    <div className="mb-8">
                <div className="mb-10 bg-slate-900 border border-slate-800 rounded-2xl p-6">

                    <div className="flex flex-wrap justify-center md:justify-between items-center gap-4 mb-5">
                        <div>
                            <h2 className="text-xl font-semibold">
                                📊 ManagerApp Intelligence
                            </h2>

                            <p className="text-slate-400 text-sm">
                                Business security monitoring for ManagerApp users, project actions and operational risk.
                            </p>
                        </div>

                        <button
                            onClick={loadManagerAppIntelligence}
                            className={`${actionButton} bg-purple-600 hover:bg-purple-700`}
                        >
                            Refresh ManagerApp Intel
                        </button>
                    </div>

                    <div className="grid sm:grid-cols-2 lg:grid-cols-4 xl:grid-cols-7 gap-4 mb-6">
                        {[
                            ["Total Events", managerIntel.overview.total_events, "text-cyan-400"],
                            ["Login Success", managerIntel.overview.login_success, "text-green-400"],
                            ["Login Failed", managerIntel.overview.login_failed, "text-yellow-400"],
                            ["Projects Created", managerIntel.overview.projects_created, "text-blue-400"],
                            ["Projects Updated", managerIntel.overview.projects_updated, "text-purple-400"],
                            ["Projects Deleted", managerIntel.overview.projects_deleted, "text-red-400"],
                            ["Suspicious Events", managerIntel.overview.suspicious_events, "text-orange-400"]
                        ].map(([title, value, color]) => (
                            <div
                                key={title}
                                className="bg-slate-950/50 border border-slate-800 rounded-2xl p-4"
                            >
                                <p className="text-slate-400 text-xs text-left">
                                    {title}
                                </p>

                                <p className={`text-2xl font-bold mt-2 ${color}`}>
                                    {value ?? 0}
                                </p>
                            </div>
                        ))}
                    </div>

                    <div className="grid lg:grid-cols-2 gap-6 mb-6">

                        <div className="bg-slate-950/50 border border-slate-800 rounded-2xl p-5">
                            <h3 className="font-semibold mb-4 text-cyan-400">
                                Top Active ManagerApp Users
                            </h3>

                            <div className="space-y-3">
                                {managerIntel.top_active_users.length === 0 && (
                                    <div className="rounded-xl bg-slate-800 p-4 text-slate-400 text-sm">
                                        No ManagerApp activity detected yet.
                                    </div>
                                )}

                                {managerIntel.top_active_users.map((user, index) => (
                                    <div
                                        key={`${user.email}-${index}`}
                                        className="bg-slate-800 rounded-xl p-4 border border-slate-700"
                                    >
                                        <div className="flex justify-between gap-3">
                                            <div>
                                                <p className="font-semibold text-white text-left">
                                                    #{index + 1} {user.username}
                                                </p>

                                                <p className="text-xs text-slate-400 text-left">
                                                    {user.email} | {user.role}
                                                </p>
                                            </div>

                                            <span className="text-cyan-300 font-bold">
                                                {user.total_actions} actions
                                            </span>
                                        </div>

                                        <p className="text-xs text-slate-400 mt-2 text-left">
                                            Last Activity: {user.last_activity}
                                        </p>
                                    </div>
                                ))}
                            </div>
                        </div>

                        <div className="bg-slate-950/50 border border-slate-800 rounded-2xl p-5">
                            <h3 className="font-semibold mb-4 text-red-400">
                                Top Suspicious ManagerApp Users
                            </h3>

                            <div className="space-y-3">
                                {managerIntel.top_suspicious_users.length === 0 && (
                                    <div className="rounded-xl bg-slate-800 p-4 text-slate-400 text-sm">
                                        No suspicious ManagerApp users detected yet.
                                    </div>
                                )}

                                {managerIntel.top_suspicious_users.map((user, index) => (
                                    <div
                                        key={`${user.email}-${index}`}
                                        className="bg-slate-800 rounded-xl p-4 border border-slate-700"
                                    >
                                        <div className="flex flex-wrap items-center justify-between gap-3 mb-3">
                                            <div>
                                                <p className="font-semibold text-white text-left">
                                                    {user.username}
                                                </p>

                                                <p className="text-xs text-slate-400 text-left">
                                                    {user.email} | {user.role}
                                                </p>
                                            </div>

                                            <span
                                                className={`text-xs font-bold px-3 py-1 rounded-full ${getRiskBadgeClass(user.risk_level)}`}
                                            >
                                                {user.risk_level} Risk
                                            </span>
                                        </div>

                                        <div className="mb-2">
                                            <div className="flex justify-between text-xs mb-1">
                                                <span className="text-slate-400">
                                                    ManagerApp Threat Score
                                                </span>

                                                <span className="font-bold text-red-300">
                                                    {user.threat_score}/100
                                                </span>
                                            </div>

                                            <div className="h-2 bg-slate-700 rounded-full overflow-hidden">
                                                <div
                                                    className={`h-full ${getRiskBarClass(user.risk_level)}`}
                                                    style={{
                                                        width: `${user.threat_score}%`
                                                    }}
                                                ></div>
                                            </div>
                                        </div>

                                        <div className="grid sm:grid-cols-4 gap-2 text-xs text-slate-300 mt-3">
                                            <div className="bg-slate-900 rounded-lg p-2">
                                                Failed Logins: {user.failed_logins}
                                            </div>

                                            <div className="bg-slate-900 rounded-lg p-2">
                                                Deleted Projects: {user.deleted_projects}
                                            </div>

                                            <div className="bg-slate-900 rounded-lg p-2">
                                                Warnings: {user.warning_events}
                                            </div>

                                            <div className="bg-slate-900 rounded-lg p-2">
                                                Critical: {user.critical_events}
                                            </div>
                                        </div>

                                        <p className="text-xs text-slate-400 mt-3 text-left">
                                            Last Detection: {user.last_detection}
                                        </p>
                                    </div>
                                ))}
                            </div>
                        </div>

                    </div>

                    <div className="grid lg:grid-cols-3 gap-6 mb-6">

                        <div className="bg-slate-950/50 border border-slate-800 rounded-2xl p-5">
                            <h3 className="font-semibold mb-4 text-yellow-400">
                                Most Deleted Projects
                            </h3>

                            <div className="space-y-3">
                                {managerIntel.most_deleted_projects.length === 0 && (
                                    <div className="rounded-xl bg-slate-800 p-4 text-slate-400 text-sm">
                                        No deleted projects detected yet.
                                    </div>
                                )}

                                {managerIntel.most_deleted_projects.map((project, index) => (
                                    <div
                                        key={`${project.project_name}-${index}`}
                                        className="bg-slate-800 rounded-xl p-3 border border-slate-700"
                                    >
                                        <div className="flex justify-between gap-3">
                                            <span className="font-semibold text-left">
                                                {project.project_name}
                                            </span>

                                            <span className="text-red-300 font-bold">
                                                {project.delete_count} deletes
                                            </span>
                                        </div>

                                        <p className="text-xs text-slate-400 mt-1 text-left">
                                            Last Deleted: {project.last_deleted}
                                        </p>
                                    </div>
                                ))}
                            </div>
                        </div>

                        <div className="bg-slate-950/50 border border-slate-800 rounded-2xl p-5">
                            <h3 className="font-semibold mb-4">
                                ManagerApp Event Distribution
                            </h3>

                            <div className="h-72">
                                <Bar
                                    data={managerEventChartData}
                                    options={chartOptions}
                                />
                            </div>
                        </div>

                        <div className="bg-slate-950/50 border border-slate-800 rounded-2xl p-5">
                            <h3 className="font-semibold mb-4">
                                Daily ManagerApp Activity
                            </h3>

                            <div className="h-72">
                                <Bar
                                    data={managerDailyChartData}
                                    options={chartOptions}
                                />
                            </div>
                        </div>

                    </div>

                    <div className="bg-slate-950/50 border border-slate-800 rounded-2xl p-5">
                        <h3 className="font-semibold mb-4 text-purple-400">
                            ManagerApp Event Timeline
                        </h3>

                        <div className="space-y-3 max-h-96 overflow-y-auto pr-2">
                            {managerIntel.latest_events.length === 0 && (
                                <div className="rounded-xl bg-slate-800 p-4 text-slate-400 text-sm">
                                    No ManagerApp timeline events available yet.
                                </div>
                            )}

                            {managerIntel.latest_events.map((event) => (
                                <div
                                    key={event.id}
                                    className="bg-slate-800 rounded-xl p-4 border border-slate-700"
                                >
                                    <div className="flex flex-wrap justify-between gap-3 mb-2">
                                        <div>
                                            <p className="font-semibold text-cyan-300 text-left">
                                                {event.event_type}
                                            </p>

                                            <p className="text-xs text-slate-400 text-left">
                                                {event.timestamp} | {event.username} | {event.email}
                                            </p>
                                        </div>

                                        <span
                                            className={
                                                event.severity_level === "critical"
                                                    ? "text-red-400 font-bold"
                                                    : event.severity_level === "warning"
                                                        ? "text-yellow-400 font-bold"
                                                        : "text-green-400 font-bold"
                                            }
                                        >
                                            {event.severity_level}
                                        </span>
                                    </div>

                                    <p className="text-sm text-slate-200 text-left">
                                        {event.action}
                                    </p>

                                    <div className="grid md:grid-cols-4 gap-2 text-xs text-slate-400 mt-3">
                                        <div className="bg-slate-900 rounded-lg p-2">
                                            Target: {event.target_resource || "-"}
                                        </div>

                                        <div className="bg-slate-900 rounded-lg p-2">
                                            IP: {event.source_ip || "-"}
                                        </div>

                                        <div className="bg-slate-900 rounded-lg p-2">
                                            Location: {event.city || "Unknown"}, {event.country || "Unknown"}
                                        </div>

                                        <div className="bg-slate-900 rounded-lg p-2">
                                            ISP: {event.isp || "Unknown"}
                                        </div>
                                    </div>
                                </div>
                            ))}
                        </div>
                    </div>

                </div>
                    </div>
                )}

                <SectionHeader
                    id="system"
                    title="🛡 System Health & Real-Time Alerts"
                    subtitle="Service health, live alerts and quick security actions."
                />

                {openSections.system && (
                    <div className="mb-8">
                <div className="mb-10 bg-slate-900 border border-slate-800 rounded-2xl p-6">

                    <div className="flex flex-wrap justify-center md:justify-between items-center gap-4 mb-4">
                        <div>
                            <h2 className="text-xl font-semibold">
                                🛡 System Health & Real-Time Alerts
                            </h2>

                            <p className="text-slate-400 text-sm">
                                Live operational status, active protection modules and recent alert notifications.
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
                    </div>
                )}

                <SectionHeader
                    id="analytics"
                    title="📈 Security Analytics & Threat Intelligence"
                    subtitle="Security KPIs, charts, suspicious users and IP addresses."
                />

                {openSections.analytics && (
                    <div className="mb-8">
                <div className="mb-8">

                    <div className="flex flex-wrap justify-center md:justify-between items-center gap-4 mb-4">
                        <div>
                            <h2 className="text-xl font-semibold">
                                📈 Security Analytics & Threat Intelligence
                            </h2>

                            <p className="text-slate-400 text-sm">
                                Security KPIs, threat intelligence, login protection and scan analytics.
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

                        
                <div className="mb-10 bg-slate-900 border border-slate-800 rounded-2xl p-6">

                    <div className="flex flex-wrap justify-center md:justify-between items-center gap-4 mb-5">
                        <div>
                            <h2 className="text-xl font-semibold">
                                🌍 Threat Intelligence Center
                            </h2>

                            <p className="text-slate-400 text-sm">
                                Top suspicious users and IP addresses ranked by calculated threat score.
                            </p>
                        </div>

                        <button
                            onClick={loadThreatIntelligence}
                            className={`${actionButton} bg-red-600 hover:bg-red-700`}
                        >
                            Refresh Threat Intel
                        </button>
                    </div>

                    <div className="grid lg:grid-cols-2 gap-6">

                        <div className="bg-slate-950/50 border border-slate-800 rounded-2xl p-5">
                            <h3 className="font-semibold mb-4 text-red-400">
                                Top Suspicious Users
                            </h3>

                            <div className="space-y-3">
                                {threatIntel.top_suspicious_users.length === 0 && (
                                    <div className="rounded-xl bg-slate-800 p-4 text-slate-400 text-sm">
                                        No suspicious users detected yet.
                                    </div>
                                )}

                                {threatIntel.top_suspicious_users.map((user) => (
                                    <div
                                        key={user.user_id}
                                        className="bg-slate-800 rounded-xl p-4 border border-slate-700"
                                    >
                                        <div className="flex flex-wrap items-center justify-between gap-3 mb-3">
                                            <div>
                                                <p className="font-semibold text-white text-left">
                                                    {user.username}
                                                </p>

                                                <p className="text-xs text-slate-400 text-left">
                                                    {user.email}
                                                </p>
                                            </div>

                                            <span
                                                className={`text-xs font-bold px-3 py-1 rounded-full ${getRiskBadgeClass(user.risk_level)}`}
                                            >
                                                {user.risk_level} Risk
                                            </span>
                                        </div>

                                        <div className="mb-2">
                                            <div className="flex justify-between text-xs mb-1">
                                                <span className="text-slate-400">
                                                    Threat Score
                                                </span>

                                                <span className="font-bold text-red-300">
                                                    {user.threat_score}/100
                                                </span>
                                            </div>

                                            <div className="h-2 bg-slate-700 rounded-full overflow-hidden">
                                                <div
                                                    className={`h-full ${getRiskBarClass(user.risk_level)}`}
                                                    style={{
                                                        width: `${user.threat_score}%`
                                                    }}
                                                ></div>
                                            </div>
                                        </div>

                                        <div className="grid sm:grid-cols-3 gap-2 text-xs text-slate-300 mt-3">
                                            <div className="bg-slate-900 rounded-lg p-2">
                                                Suspicious Files: {user.suspicious_files}
                                            </div>

                                            <div className="bg-slate-900 rounded-lg p-2">
                                                Failed Logins: {user.failed_logins}
                                            </div>

                                            <div className="bg-slate-900 rounded-lg p-2">
                                                Brute Force: {user.brute_force_blocks}
                                            </div>
                                        </div>

                                        <p className="text-xs text-slate-400 mt-3 text-left">
                                            Last Detection: {user.last_detection}
                                        </p>
                                    </div>
                                ))}
                            </div>
                        </div>

                        <div className="bg-slate-950/50 border border-slate-800 rounded-2xl p-5">
                            <h3 className="font-semibold mb-4 text-yellow-400">
                                Top Suspicious IPs
                            </h3>

                            <div className="space-y-3">
                                {threatIntel.top_suspicious_ips.length === 0 && (
                                    <div className="rounded-xl bg-slate-800 p-4 text-slate-400 text-sm">
                                        No suspicious IP addresses detected yet.
                                    </div>
                                )}

                                {threatIntel.top_suspicious_ips.map((ip) => (
                                    <div
                                        key={ip.source_ip}
                                        className="bg-slate-800 rounded-xl p-4 border border-slate-700"
                                    >
                                        <div className="flex flex-wrap items-center justify-between gap-3 mb-3">
                                            <div>
                                                <p className="font-semibold text-white text-left">
                                                    {ip.source_ip}
                                                </p>

                                                <p className="text-xs text-slate-400 text-left">
                                                    {ip.country} | {ip.city} | {ip.isp}
                                                </p>
                                            </div>

                                            <span
                                                className={`text-xs font-bold px-3 py-1 rounded-full ${getRiskBadgeClass(ip.risk_level)}`}
                                            >
                                                {ip.risk_level} Risk
                                            </span>
                                        </div>

                                        <div className="mb-2">
                                            <div className="flex justify-between text-xs mb-1">
                                                <span className="text-slate-400">
                                                    Threat Score
                                                </span>

                                                <span className="font-bold text-yellow-300">
                                                    {ip.threat_score}/100
                                                </span>
                                            </div>

                                            <div className="h-2 bg-slate-700 rounded-full overflow-hidden">
                                                <div
                                                    className={`h-full ${getRiskBarClass(ip.risk_level)}`}
                                                    style={{
                                                        width: `${ip.threat_score}%`
                                                    }}
                                                ></div>
                                            </div>
                                        </div>

                                        <div className="grid sm:grid-cols-3 gap-2 text-xs text-slate-300 mt-3">
                                            <div className="bg-slate-900 rounded-lg p-2">
                                                Failed Logins: {ip.failed_logins}
                                            </div>

                                            <div className="bg-slate-900 rounded-lg p-2">
                                                Brute Force: {ip.brute_force_events}
                                            </div>

                                            <div className="bg-slate-900 rounded-lg p-2">
                                                Events: {ip.suspicious_events}
                                            </div>
                                        </div>

                                        <p className="text-xs text-slate-400 mt-3 text-left">
                                            Last Detection: {ip.last_detection}
                                        </p>
                                    </div>
                                ))}
                            </div>
                        </div>

                    </div>
                </div>


                <div className="mb-10 bg-slate-900 border border-slate-800 rounded-2xl p-6">
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
                    </div>
                )}

                <SectionHeader
                    id="users"
                    title="👥 User Management"
                    subtitle="Registered users, roles, blocking actions and reports."
                />

                {openSections.users && (
                    <div className="mb-8">
                <div className="bg-slate-900 border border-slate-800 rounded-2xl p-6">

                    <h2 className="text-xl font-semibold mb-4">
                        👥 User Management
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
                    </div>
                )}

                <SectionHeader
                    id="audit"
                    title="📖 Audit Journal"
                    subtitle="Complete activity history with IP, geolocation, device and severity."
                />

                {openSections.audit && (
                    <div className="mb-8">
                <div className="mt-10 bg-slate-900 border border-slate-800 rounded-2xl p-6">

                    <div className="flex flex-wrap justify-center md:justify-between items-center gap-4 mb-4">

                        <div>
                            <h2 className="text-xl font-semibold">
                                📖 Audit Journal
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
                                    <th className="text-left py-3">Browser</th>
                                    <th className="text-left py-3">OS</th>
                                    <th className="text-left py-3">Device</th>
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
                                            {log.browser || "Unknown"}
                                        </td>

                                        <td className="py-3">
                                            {log.operating_system || "Unknown"}
                                        </td>

                                        <td className="py-3">
                                            {log.device_type || "Unknown"}
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
                                            colSpan="15"
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
                    </div>
                )}

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
                managerIntel={managerIntel}
                behaviorAnalysis={behaviorAnalysis}
                executiveDashboard={executiveDashboard}
                auditLogs={auditLogs}
                activity={auditLogs.map((log) =>
                    `${log.action_type}: ${log.action}`
                )}
                isAdmin={true}
            />

        </div>
    );
}
