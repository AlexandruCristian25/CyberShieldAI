import { useState } from "react";

export default function AssistantBubble({
    user,
    stats,
    scans = [],
    activity = [],
    users = [],
    analytics = null,
    auditLogs = [],
    isAdmin = false
}) {

    const [open, setOpen] = useState(false);
    const [messages, setMessages] = useState([
        {
            sender: "assistant",
            text: "Hello! I am your CyberShield AI Assistant. I can analyze real dashboard data, latest scans, threats, reports, audit activity and admin security metrics."
        }
    ]);

    const [input, setInput] = useState("");

    const getLatestScan = () => {
        if (!scans || scans.length === 0) {
            return null;
        }

        return scans[0];
    };

    const getSuspiciousScans = () => {
        if (!scans || scans.length === 0) {
            return [];
        }

        return scans.filter((scan) =>
            scan.status === "Suspicious" ||
            scan.status === "Malicious"
        );
    };

    const getBlockedUsers = () => {
        if (!users || users.length === 0) {
            return [];
        }

        return users.filter((userItem) =>
            userItem.is_blocked === 1 ||
            userItem.is_blocked === true
        );
    };

    const getCriticalLogs = () => {
        const sourceLogs =
            auditLogs && auditLogs.length > 0
                ? auditLogs
                : activity;

        if (!sourceLogs || sourceLogs.length === 0) {
            return [];
        }

        return sourceLogs.filter((item) => {
            if (typeof item === "string") {
                return (
                    item.toLowerCase().includes("critical") ||
                    item.toLowerCase().includes("brute") ||
                    item.toLowerCase().includes("blocked")
                );
            }

            return (
                item.severity_level === "critical" ||
                item.action_type?.toLowerCase().includes("brute") ||
                item.action_type?.toLowerCase().includes("block")
            );
        });
    };

    const formatScanSummary = (scan) => {
        if (!scan) {
            return "No scan data is available yet.";
        }

        return (
            `File: ${scan.filename || "Unknown"}\n` +
            `Status: ${scan.status || "Unknown"}\n` +
            `Size: ${scan.size || scan.filesize || "Unknown"} bytes\n` +
            `Reason: ${scan.reason || "No reason provided"}\n` +
            `SHA-256: ${scan.sha256?.substring(0, 32) || scan.file_hash?.substring(0, 32) || "Unknown"}...\n` +
            `Date: ${scan.scan_date || scan.timestamp || "Unknown"}`
        );
    };

    const buildAdminSummary = () => {
        const blockedUsers = getBlockedUsers();
        const criticalLogs = getCriticalLogs();

        return (
            "Admin security summary:\n\n" +
            `Total users: ${analytics?.total_users ?? users.length ?? 0}\n` +
            `Total admins: ${analytics?.total_admins ?? "N/A"}\n` +
            `Blocked users: ${analytics?.blocked_users ?? blockedUsers.length}\n` +
            `Total scans: ${analytics?.total_scans ?? stats?.files_scanned ?? 0}\n` +
            `Threats detected: ${analytics?.threats_detected ?? stats?.threats_blocked ?? 0}\n` +
            `Login attempts: ${analytics?.login_attempts ?? "N/A"}\n` +
            `Failed logins: ${analytics?.failed_logins ?? "N/A"}\n` +
            `Brute force blocks: ${analytics?.brute_force_blocks ?? criticalLogs.length}\n\n` +
            "Recommended action:\n" +
            "Review critical audit logs, blocked users and suspicious scans before unblocking any account."
        );
    };

    const buildBlockedUsersSummary = () => {
        const blockedUsers = getBlockedUsers();

        if (!isAdmin) {
            return "Blocked user information is available only in the Admin Panel.";
        }

        if (!blockedUsers || blockedUsers.length === 0) {
            return "There are currently no blocked users in the data available to the assistant.";
        }

        return (
            `There are ${blockedUsers.length} blocked user(s):\n\n` +
            blockedUsers
                .slice(0, 10)
                .map((userItem) =>
                    `- ${userItem.username || "Unknown"} | ${userItem.email || "No email"} | ID: ${userItem.id}`
                )
                .join("\n")
        );
    };

    const buildCriticalLogsSummary = () => {
        const criticalLogs = getCriticalLogs();

        if (!criticalLogs || criticalLogs.length === 0) {
            return "No critical activity was found in the currently available assistant data.";
        }

        return (
            `I found ${criticalLogs.length} critical or high-risk event(s):\n\n` +
            criticalLogs
                .slice(0, 8)
                .map((log) => {
                    if (typeof log === "string") {
                        return `- ${log}`;
                    }

                    return (
                        `- ${log.timestamp || "Unknown date"} | ` +
                        `${log.action_type || "Unknown action"} | ` +
                        `${log.action || "No details"} | ` +
                        `IP: ${log.source_ip || "-"}`
                    );
                })
                .join("\n")
        );
    };

    const buildResponse = (question) => {
        const q = question.toLowerCase();
        const latestScan = getLatestScan();
        const suspiciousScans = getSuspiciousScans();

        if (
            q.includes("admin summary") ||
            q.includes("security summary") ||
            q.includes("summary admin") ||
            q.includes("sumar admin") ||
            q.includes("sumar securitate")
        ) {
            return buildAdminSummary();
        }

        if (
            q.includes("blocked users") ||
            q.includes("blocked user") ||
            q.includes("utilizatori blocati") ||
            q.includes("useri blocati") ||
            q.includes("conturi blocate")
        ) {
            return buildBlockedUsersSummary();
        }

        if (
            q.includes("critical") ||
            q.includes("critic") ||
            q.includes("brute force") ||
            q.includes("brute") ||
            q.includes("high risk")
        ) {
            return buildCriticalLogsSummary();
        }

        if (
            q.includes("latest scan") ||
            q.includes("last scan") ||
            q.includes("ultimul fisier") ||
            q.includes("ultima scanare") ||
            q.includes("ultimul scan")
        ) {
            return (
                "Latest scan summary:\n\n" +
                formatScanSummary(latestScan)
            );
        }

        if (
            q.includes("status") ||
            q.includes("clean") ||
            q.includes("suspicious") ||
            q.includes("malicious")
        ) {
            return (
                "Scan statuses mean:\n\n" +
                "Clean = no obvious threat indicators were found.\n" +
                "Suspicious = the file has risky indicators, such as dangerous extension or suspicious VirusTotal result.\n" +
                "Malicious = malware was detected by security engines.\n\n" +
                `Current suspicious/malicious scans available here: ${suspiciousScans.length}.`
            );
        }

        if (
            q.includes("sha") ||
            q.includes("hash") ||
            q.includes("fingerprint") ||
            q.includes("amprenta")
        ) {
            if (latestScan) {
                return (
                    "SHA-256 is the digital fingerprint of a file.\n\n" +
                    "Latest available fingerprint:\n" +
                    `${latestScan.sha256 || latestScan.file_hash || "Unknown"}\n\n` +
                    "It helps identify the file uniquely and compare it with VirusTotal results."
                );
            }

            return (
                "SHA-256 is the digital fingerprint of a file. " +
                "CyberShield AI calculates it for every uploaded file so it can be uniquely identified, audited and checked with VirusTotal."
            );
        }

        if (
            q.includes("report") ||
            q.includes("pdf") ||
            q.includes("csv") ||
            q.includes("raport")
        ) {
            return (
                "Reports help with incident documentation:\n\n" +
                "PDF reports are useful for security review and presentation.\n" +
                "CSV exports are useful for audit, filtering, Excel analysis and evidence collection.\n\n" +
                "Latest available scan for reporting:\n\n" +
                formatScanSummary(latestScan)
            );
        }

        if (
            q.includes("score") ||
            q.includes("security score") ||
            q.includes("scor")
        ) {
            return (
                `Current security score is ${stats?.security_score ?? 0}%.\n\n` +
                `Files scanned: ${stats?.files_scanned ?? analytics?.total_scans ?? 0}\n` +
                `Threats detected: ${stats?.threats_blocked ?? analytics?.threats_detected ?? 0}\n\n` +
                "The score decreases when threats are detected. A high score means fewer suspicious or malicious files were found."
            );
        }

        if (
            q.includes("threat") ||
            q.includes("malware") ||
            q.includes("virus") ||
            q.includes("amenintari")
        ) {
            return (
                `CyberShield AI has currently detected ${stats?.threats_blocked ?? analytics?.threats_detected ?? 0} threat(s).\n\n` +
                `Suspicious scans in current view: ${suspiciousScans.length}\n\n` +
                "Recommended action:\n" +
                "1. Do not open suspicious files.\n" +
                "2. Download the PDF report.\n" +
                "3. Review SHA-256 and reason.\n" +
                "4. If needed, block the user from Admin Panel."
            );
        }

        if (
            q.includes("scan") ||
            q.includes("file") ||
            q.includes("fisier")
        ) {
            if (!latestScan) {
                return (
                    "No recent scans were found yet. Upload a file in the File Scanner section and press Scan File."
                );
            }

            return (
                "Latest scan summary:\n\n" +
                formatScanSummary(latestScan) +
                "\n\nYou can download the PDF report from the Scan History table."
            );
        }

        if (
            q.includes("password") ||
            q.includes("login") ||
            q.includes("parola")
        ) {
            return (
                "Login security summary:\n\n" +
                `Successful logins: ${analytics?.successful_logins ?? "N/A"}\n` +
                `Failed logins: ${analytics?.failed_logins ?? "N/A"}\n` +
                `Brute force blocks: ${analytics?.brute_force_blocks ?? "N/A"}\n\n` +
                "Brute Force Protection blocks an account after multiple failed login attempts and sends an email alert to the admin."
            );
        }

        if (
            q.includes("audit") ||
            q.includes("journal") ||
            q.includes("log") ||
            q.includes("jurnal")
        ) {
            if (isAdmin) {
                return (
                    "Audit Journal records security events such as login attempts, blocked accounts, file scans, malware detections and admin actions.\n\n" +
                    buildCriticalLogsSummary()
                );
            }

            return (
                "Audit logs are available only for administrators. They are used for monitoring system activity, detecting suspicious behavior and generating security reports."
            );
        }

        if (
            q.includes("activity") ||
            q.includes("recent") ||
            q.includes("activitate")
        ) {
            const latestActivity =
                activity && activity.length > 0
                    ? activity.slice(0, 5).join("\n")
                    : "No recent activity available.";

            return (
                "Recent activity:\n\n" +
                latestActivity
            );
        }

        if (
            q.includes("geo") ||
            q.includes("ip") ||
            q.includes("location") ||
            q.includes("locatie")
        ) {
            return (
                "CyberShield AI can show IP geolocation in Admin Audit Journal when available:\n\n" +
                "- Country\n" +
                "- City\n" +
                "- ISP\n" +
                "- Coordinates\n\n" +
                "Localhost addresses such as 127.0.0.1 usually appear as Local / Unknown."
            );
        }

        if (
            q.includes("help") ||
            q.includes("ce poti") ||
            q.includes("what can") ||
            q.includes("ajutor")
        ) {
            return (
                "I can help with real CyberShield data:\n\n" +
                "- latest scan summary\n" +
                "- suspicious or malicious detections\n" +
                "- security score\n" +
                "- SHA-256 fingerprints\n" +
                "- PDF and CSV reports\n" +
                "- brute force protection\n" +
                "- recent activity\n" +
                "- admin security summary\n" +
                "- blocked users\n" +
                "- critical audit logs"
            );
        }

        return (
            "I can help you with CyberShield AI security information. Try asking:\n\n" +
            "- What is the latest scan?\n" +
            "- How many threats were detected?\n" +
            "- Show security summary\n" +
            "- Show blocked users\n" +
            "- Show critical logs\n" +
            "- Explain SHA-256\n" +
            "- What should I do after malware detection?"
        );
    };

    const sendMessage = () => {
        if (!input.trim()) {
            return;
        }

        const userMessage = {
            sender: "user",
            text: input
        };

        const assistantMessage = {
            sender: "assistant",
            text: buildResponse(input)
        };

        setMessages((prev) => [
            ...prev,
            userMessage,
            assistantMessage
        ]);

        setInput("");
    };

    const quickQuestion = (question) => {
        const userMessage = {
            sender: "user",
            text: question
        };

        const assistantMessage = {
            sender: "assistant",
            text: buildResponse(question)
        };

        setMessages((prev) => [
            ...prev,
            userMessage,
            assistantMessage
        ]);
    };

    return (
        <div className="fixed bottom-6 right-6 z-50">

            {open && (
                <div className="mb-4 w-80 md:w-96 rounded-2xl border border-cyan-500/30 bg-slate-900 shadow-2xl overflow-hidden">

                    <div className="bg-slate-950 border-b border-slate-800 p-4 flex justify-between items-center">
                        <div>
                            <h3 className="text-cyan-400 font-bold">
                                CyberShield Assistant
                            </h3>

                            <p className="text-xs text-slate-400">
                                Security helper for reports, scans and activity
                            </p>
                        </div>

                        <button
                            onClick={() => setOpen(false)}
                            className="text-slate-400 hover:text-white text-sm"
                        >
                            ✕
                        </button>
                    </div>

                    <div className="p-4 h-80 overflow-y-auto space-y-3">
                        {messages.map((message, index) => (
                            <div
                                key={index}
                                className={
                                    message.sender === "assistant"
                                        ? "bg-slate-800 text-slate-100 rounded-xl p-3 text-sm whitespace-pre-line"
                                        : "bg-cyan-600 text-white rounded-xl p-3 text-sm ml-8 whitespace-pre-line"
                                }
                            >
                                {message.text}
                            </div>
                        ))}
                    </div>

                    <div className="px-4 pb-3 flex flex-wrap gap-2">
                        <button
                            onClick={() => quickQuestion("What is the latest scan?")}
                            className="bg-slate-800 hover:bg-slate-700 text-xs px-3 py-1 rounded-lg"
                        >
                            Latest scan
                        </button>

                        <button
                            onClick={() => quickQuestion("Show security summary")}
                            className="bg-slate-800 hover:bg-slate-700 text-xs px-3 py-1 rounded-lg"
                        >
                            Security summary
                        </button>

                        <button
                            onClick={() => quickQuestion("Show critical logs")}
                            className="bg-slate-800 hover:bg-slate-700 text-xs px-3 py-1 rounded-lg"
                        >
                            Critical logs
                        </button>
                    </div>

                    <div className="border-t border-slate-800 p-3 flex gap-2">
                        <input
                            value={input}
                            onChange={(e) => setInput(e.target.value)}
                            onKeyDown={(e) => {
                                if (e.key === "Enter") {
                                    sendMessage();
                                }
                            }}
                            placeholder="Ask CyberShield..."
                            className="flex-1 rounded-lg bg-slate-800 border border-slate-700 px-3 py-2 text-sm outline-none focus:border-cyan-500"
                        />

                        <button
                            onClick={sendMessage}
                            className="bg-cyan-600 hover:bg-cyan-700 px-3 py-2 rounded-lg text-sm font-semibold"
                        >
                            Send
                        </button>
                    </div>
                </div>
            )}

            <button
                onClick={() => setOpen(!open)}
                className="w-16 h-16 rounded-full bg-cyan-600 hover:bg-cyan-700 shadow-2xl border border-cyan-300/40 flex items-center justify-center text-3xl transition"
                title="CyberShield Assistant"
            >
                🛡️
            </button>
        </div>
    );
}
