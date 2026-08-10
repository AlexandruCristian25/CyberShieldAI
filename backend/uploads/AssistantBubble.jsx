import { useState } from "react";

export default function AssistantBubble({
    user,
    stats,
    scans,
    activity,
    isAdmin = false
}) {

    const [open, setOpen] = useState(false);
    const [messages, setMessages] = useState([
        {
            sender: "assistant",
            text: "Hello! I am your CyberShield AI Assistant. I can help you understand scans, reports, security score, threats, audit logs and recommendations."
        }
    ]);

    const [input, setInput] = useState("");

    const getLatestScan = () => {
        if (!scans || scans.length === 0) {
            return null;
        }

        return scans[0];
    };

    const buildResponse = (question) => {
        const q = question.toLowerCase();
        const latestScan = getLatestScan();

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
                "If a file is Suspicious or Malicious, you should avoid opening it and review the PDF report."
            );
        }

        if (
            q.includes("sha") ||
            q.includes("hash") ||
            q.includes("fingerprint")
        ) {
            return (
                "SHA-256 is the digital fingerprint of a file. " +
                "CyberShield AI calculates it for every uploaded file so the file can be uniquely identified, compared, audited and checked with VirusTotal."
            );
        }

        if (
            q.includes("report") ||
            q.includes("pdf") ||
            q.includes("csv")
        ) {
            return (
                "Reports help with incident documentation:\n\n" +
                "PDF reports are useful for security review and presentation.\n" +
                "CSV exports are useful for audit, filtering, Excel analysis and evidence collection.\n\n" +
                "You can download scan reports from the Scan History section."
            );
        }

        if (
            q.includes("score") ||
            q.includes("security score")
        ) {
            return (
                `Current security score is ${stats?.security_score ?? 0}%.\n\n` +
                "The score decreases when threats are detected. " +
                "A high score means fewer suspicious or malicious files were found."
            );
        }

        if (
            q.includes("threat") ||
            q.includes("malware") ||
            q.includes("virus")
        ) {
            return (
                `CyberShield AI has currently blocked/detected ${stats?.threats_blocked ?? 0} threat(s).\n\n` +
                "Recommended action:\n" +
                "1. Do not open suspicious files.\n" +
                "2. Download the PDF report.\n" +
                "3. Review SHA-256 and reason.\n" +
                "4. If needed, notify the administrator."
            );
        }

        if (
            q.includes("scan") ||
            q.includes("file")
        ) {
            if (!latestScan) {
                return (
                    "No recent scans were found yet. Upload a file in the File Scanner section and press Scan File."
                );
            }

            return (
                "Latest scan summary:\n\n" +
                `File: ${latestScan.filename}\n` +
                `Status: ${latestScan.status}\n` +
                `Reason: ${latestScan.reason}\n` +
                `SHA-256: ${latestScan.sha256?.substring(0, 24)}...\n\n` +
                "You can download the PDF report from the Scan History table."
            );
        }

        if (
            q.includes("brute") ||
            q.includes("password") ||
            q.includes("login")
        ) {
            return (
                "Brute Force Protection blocks an account after multiple failed login attempts. " +
                "This prevents attackers from repeatedly trying passwords. " +
                "When triggered, CyberShield AI creates an audit event and sends an email alert to the admin."
            );
        }

        if (
            q.includes("audit") ||
            q.includes("journal") ||
            q.includes("log")
        ) {
            if (isAdmin) {
                return (
                    "Audit Journal records important security events: login attempts, blocked accounts, file scans, malware detections and admin actions. " +
                    "Admins can export audit logs as CSV for investigation and reporting."
                );
            }

            return (
                "Audit logs are available only for administrators. " +
                "They are used for monitoring system activity, detecting suspicious behavior and generating security reports."
            );
        }

        if (
            q.includes("activity") ||
            q.includes("recent")
        ) {
            const latestActivity =
                activity && activity.length > 0
                    ? activity.slice(0, 3).join("\n")
                    : "No recent activity available.";

            return (
                "Recent activity:\n\n" +
                latestActivity
            );
        }

        if (
            q.includes("help") ||
            q.includes("ce poti") ||
            q.includes("what can")
        ) {
            return (
                "I can help with:\n\n" +
                "- explaining scan statuses\n" +
                "- understanding SHA-256 fingerprints\n" +
                "- explaining PDF and CSV reports\n" +
                "- summarizing latest scan activity\n" +
                "- explaining brute force protection\n" +
                "- giving recommendations after suspicious detections\n" +
                "- helping admins understand audit logs"
            );
        }

        return (
            "I can help you with CyberShield AI security information. Try asking:\n\n" +
            "- What does Suspicious mean?\n" +
            "- Explain SHA-256\n" +
            "- What should I do after malware detection?\n" +
            "- Explain security score\n" +
            "- Show latest scan summary\n" +
            "- Explain brute force protection"
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
                            onClick={() => quickQuestion("Explain latest scan")}
                            className="bg-slate-800 hover:bg-slate-700 text-xs px-3 py-1 rounded-lg"
                        >
                            Latest scan
                        </button>

                        <button
                            onClick={() => quickQuestion("Explain security score")}
                            className="bg-slate-800 hover:bg-slate-700 text-xs px-3 py-1 rounded-lg"
                        >
                            Security score
                        </button>

                        <button
                            onClick={() => quickQuestion("What should I do after malware detection?")}
                            className="bg-slate-800 hover:bg-slate-700 text-xs px-3 py-1 rounded-lg"
                        >
                            Malware help
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
