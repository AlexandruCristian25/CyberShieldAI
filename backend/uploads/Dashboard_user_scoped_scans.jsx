import { useNavigate } from "react-router-dom";
import { useEffect, useState } from "react";
import axios from "axios";
import AssistantBubble from "../components/AssistantBubble";

const API_URL = "http://127.0.0.1:5000";

export default function Dashboard() {
    const navigate = useNavigate();

    const [stats, setStats] = useState({
        threats_blocked: 0,
        files_scanned: 0,
        security_score: 0
    });

    const [selectedFile, setSelectedFile] = useState(null);
    const [scanResult, setScanResult] = useState("");
    const [scans, setScans] = useState([]);

    const [activity, setActivity] = useState([
        "System initialized",
        "Dashboard loaded"
    ]);

    const user = JSON.parse(localStorage.getItem("user"));

    useEffect(() => {
        if (!user) {
            navigate("/");
            return;
        }

        loadStats();
        loadScans();
    }, []);

    const smallButton =
        "text-white text-sm font-medium px-3 py-2 rounded-lg transition inline-flex items-center w-auto";

    const loadStats = async () => {
        try {
            const response = await axios.get(
                `${API_URL}/stats?user_id=${user?.id}`
            );
            setStats(response.data);
        } catch (error) {
            console.error("Unable to load statistics", error);
        }
    };

    const loadScans = async () => {
        try {
            const response = await axios.get(
                `${API_URL}/scans?user_id=${user?.id}`
            );
            setScans(response.data);
        } catch (error) {
            console.error("Unable to load scans", error);
        }
    };

    const handleFileSelect = (e) => {
        const file = e.target.files[0];
        if (!file) return;
        setSelectedFile(file);
    };

    const scanFile = async () => {
        if (!selectedFile) {
            setScanResult("Please select a file first.");
            return;
        }

        try {
            const formData = new FormData();

            formData.append("file", selectedFile);

            if (user?.id) {
                formData.append("user_id", user.id);
            }

            const response = await axios.post(
                `${API_URL}/scan`,
                formData,
                {
                    headers: {
                        "Content-Type": "multipart/form-data"
                    }
                }
            );

            setScanResult(
                `${response.data.message} | Status: ${response.data.status} | Reason: ${response.data.reason}`
            );

            setActivity((prev) => [
                `Scanned file: ${selectedFile.name}`,
                `Status: ${response.data.status}`,
                ...prev
            ]);

            loadStats();
            loadScans();
        } catch (error) {
            console.error(error);
            setScanResult("Scan failed.");
        }
    };

    const downloadScanHistory = () => {
        window.open(
            `${API_URL}/export/scans?user_id=${user?.id}`,
            "_blank"
        );
    };

    const downloadLoginAudit = () => {
        window.open(`${API_URL}/export/logins`, "_blank");
    };

    const downloadReport = (scanId) => {
        window.open(
            `${API_URL}/report/${scanId}?user_id=${user?.id}`,
            "_blank"
        );
    };

    const logout = () => {
        localStorage.removeItem("user");
        localStorage.removeItem("token");

        navigate("/");
    };

    return (
        <div className="min-h-screen bg-slate-950 text-white">
            <header className="border-b border-slate-800">
                <div className="max-w-7xl mx-auto px-6 py-4 flex justify-between items-center">
                    <div>
                        <h1 className="text-3xl font-bold text-cyan-400">
                            CyberShield AI
                        </h1>

                        <p className="text-slate-400">
                            Enterprise Security Dashboard
                        </p>

                        <p className="text-cyan-300 mt-2">
                            Welcome{" "}
                            <span className="font-bold">
                                {user?.username || "User"}
                            </span>
                        </p>
                    </div>

                    <button
                        onClick={logout}
                        className={`${smallButton} bg-red-600 hover:bg-red-700`}
                    >
                        Logout
                    </button>
                </div>
            </header>

            <main className="max-w-7xl mx-auto p-6">
                <div className="grid md:grid-cols-3 gap-6">
                    <div className="bg-slate-900 border border-slate-800 rounded-2xl p-6">
                        <h2 className="text-cyan-400 text-lg font-semibold">
                            Threats Blocked
                        </h2>

                        <p className="text-4xl font-bold mt-3">
                            {stats.threats_blocked}
                        </p>
                    </div>

                    <div className="bg-slate-900 border border-slate-800 rounded-2xl p-6">
                        <h2 className="text-green-400 text-lg font-semibold">
                            Files Scanned
                        </h2>

                        <p className="text-4xl font-bold mt-3">
                            {stats.files_scanned}
                        </p>
                    </div>

                    <div className="bg-slate-900 border border-slate-800 rounded-2xl p-6">
                        <h2 className="text-purple-400 text-lg font-semibold">
                            Security Score
                        </h2>

                        <p className="text-4xl font-bold mt-3">
                            {stats.security_score}%
                        </p>
                    </div>
                </div>

                <div className="mt-8 bg-slate-900 border border-slate-800 rounded-2xl p-6">
                    <h2 className="text-xl font-semibold mb-4">
                        Export Security Reports
                    </h2>

                    <div className="flex flex-wrap gap-3">
                        <button
                            onClick={downloadScanHistory}
                            className={`${smallButton} bg-green-600 hover:bg-green-700`}
                        >
                            Download Scan History
                        </button>

                        <button
                            onClick={downloadLoginAudit}
                            className={`${smallButton} bg-green-600 hover:bg-green-700`}
                        >
                            Download Login Audit
                        </button>
                    </div>
                </div>

                <div className="mt-8 bg-slate-900 border border-slate-800 rounded-2xl p-6">
                    <h2 className="text-xl font-semibold mb-4">
                        File Scanner
                    </h2>

                    <input
                        type="file"
                        onChange={handleFileSelect}
                        className="mb-4 block"
                    />

                    <button
                        onClick={scanFile}
                        className={`${smallButton} bg-cyan-600 hover:bg-cyan-700`}
                    >
                        Scan File
                    </button>

                    {selectedFile && (
                        <p className="mt-3 text-slate-300">
                            Selected: {selectedFile.name}
                        </p>
                    )}

                    {scanResult && (
                        <div className="mt-4 p-3 rounded-xl bg-slate-800">
                            {scanResult}
                        </div>
                    )}
                </div>

                <div className="mt-8 bg-slate-900 border border-slate-800 rounded-2xl p-6">
                    <h2 className="text-xl font-semibold mb-4">
                        Recent Activity
                    </h2>

                    <div className="space-y-3">
                        {activity.map((item, index) => (
                            <div
                                key={index}
                                className="p-3 rounded-xl bg-slate-800"
                            >
                                {item}
                            </div>
                        ))}
                    </div>
                </div>

                <div className="mt-8 bg-slate-900 border border-slate-800 rounded-2xl p-6">
                    <h2 className="text-xl font-semibold mb-4">
                        Scan History
                    </h2>

                    <div className="overflow-x-auto">
                        <table className="w-full">
                            <thead>
                                <tr className="border-b border-slate-700">
                                    <th className="text-left py-3">File</th>
                                    <th className="text-left py-3">Status</th>
                                    <th className="text-left py-3">Size</th>
                                    <th className="text-left py-3">SHA256</th>
                                    <th className="text-left py-3">Reason</th>
                                    <th className="text-left py-3">Date</th>
                                    <th className="text-left py-3">Report</th>
                                </tr>
                            </thead>

                            <tbody>
                                {scans.length === 0 && (
                                    <tr>
                                        <td
                                            colSpan="7"
                                            className="py-6 text-center text-slate-400"
                                        >
                                            No scans found for this user yet.
                                        </td>
                                    </tr>
                                )}

                                {scans.map((scan, index) => (
                                    <tr
                                        key={index}
                                        className="border-b border-slate-800"
                                    >
                                        <td className="py-3">
                                            {scan.filename}
                                        </td>

                                        <td className="py-3">
                                            <span
                                                className={
                                                    scan.status === "Suspicious" ||
                                                    scan.status === "Malicious"
                                                        ? "text-red-400"
                                                        : "text-green-400"
                                                }
                                            >
                                                {scan.status}
                                            </span>
                                        </td>

                                        <td className="py-3">
                                            {scan.size} bytes
                                        </td>

                                        <td className="py-3 text-xs">
                                            {scan.sha256?.substring(0, 16)}...
                                        </td>

                                        <td className="py-3 text-sm text-slate-300">
                                            {scan.reason}
                                        </td>

                                        <td className="py-3">
                                            {scan.scan_date}
                                        </td>

                                        <td className="py-3">
                                            <button
                                                onClick={() =>
                                                    downloadReport(scan.id)
                                                }
                                                className="bg-green-600 hover:bg-green-700 text-white text-xs font-medium px-3 py-1 rounded-lg transition"
                                            >
                                                PDF
                                            </button>
                                        </td>
                                    </tr>
                                ))}
                            </tbody>
                        </table>
                    </div>
                </div>

                <div className="mt-8 bg-slate-900 border border-slate-800 rounded-2xl p-6">
                    <h2 className="text-xl font-semibold mb-4">
                        System Status
                    </h2>

                    <div className="flex items-center gap-3">
                        <div className="w-3 h-3 bg-green-500 rounded-full"></div>

                        <span>
                            All CyberShield AI services are operational.
                        </span>
                    </div>
                </div>
            </main>

            <AssistantBubble
                user={user}
                stats={stats}
                scans={scans}
                activity={activity}
                isAdmin={false}
            />
        </div>
    );
}
