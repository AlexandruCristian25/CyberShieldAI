import { useState } from "react";
import { useNavigate } from "react-router-dom";
import { motion } from "framer-motion";

import { loginUser } from "../services/auth";
import logo from "../assets/cybershield-logo.png";

export default function Login() {

    const navigate = useNavigate();

    const [email, setEmail] = useState("");
    const [pass, setPass] = useState("");
    const [error, setError] = useState("");
    const [loading, setLoading] = useState(false);

    const buttonBase =
        "text-white text-sm font-semibold px-4 py-2 rounded-xl transition inline-flex items-center justify-center";

    const handleLogin = async () => {

        try {

            setLoading(true);
            setError("");

            if (!email || !pass) {
                setError(
                    "Please enter email and password."
                );

                return;
            }

            const result = await loginUser(
                email,
                pass
            );

            if (!result.success) {
                setError(
                    result.message ||
                    "Login failed"
                );

                return;
            }

            if (result.user) {
                localStorage.setItem(
                    "user",
                    JSON.stringify(
                        result.user
                    )
                );

                if (result.user.role === "admin") {
                    navigate("/admin");
                } else {
                    navigate("/dashboard");
                }
            }

        } catch (err) {

            setError(
                err?.response?.data?.message ||
                "Server connection error"
            );

        } finally {

            setLoading(false);
        }
    };

    return (
        <div className="min-h-screen flex items-center justify-center bg-gradient-to-br from-slate-950 via-slate-900 to-black text-white p-4">

            <motion.div
                className="w-full max-w-md mx-auto bg-slate-900/90 backdrop-blur-xl rounded-3xl shadow-2xl border border-cyan-500/20 p-8"
                initial={{
                    opacity: 0,
                    y: -20
                }}
                animate={{
                    opacity: 1,
                    y: 0
                }}
                transition={{
                    duration: 0.6
                }}
            >

                <div className="flex justify-center items-center mb-4">
                    <img
                        src={logo}
                        alt="CyberShield AI Logo"
                        className="w-20 h-20 object-contain"
                    />
                </div>

                <h1 className="text-3xl font-bold text-cyan-400 mb-1 text-center">
                    CyberShield AI
                </h1>

                <p className="text-slate-400 text-center mb-6">
                    Enterprise Security Platform
                </p>

                <div className="space-y-4">

                    <input
                        type="email"
                        placeholder="Email"
                        value={email}
                        autoComplete="username"
                        className="w-full px-4 py-3 bg-slate-800 border border-slate-700 rounded-xl text-white placeholder-slate-400 focus:outline-none focus:ring-2 focus:ring-cyan-500"
                        onChange={(e) =>
                            setEmail(
                                e.target.value
                            )
                        }
                    />

                    <input
                        type="password"
                        placeholder="Password"
                        value={pass}
                        autoComplete="current-password"
                        className="w-full px-4 py-3 bg-slate-800 border border-slate-700 rounded-xl text-white placeholder-slate-400 focus:outline-none focus:ring-2 focus:ring-cyan-500"
                        onChange={(e) =>
                            setPass(
                                e.target.value
                            )
                        }
                    />

                </div>

                <div className="mt-6 flex justify-center">
                    <button
                        className={`${buttonBase} bg-cyan-600 hover:bg-cyan-700 disabled:opacity-50 min-w-[180px]`}
                        onClick={handleLogin}
                        disabled={loading}
                    >
                        {loading
                            ? "Authenticating..."
                            : "Secure Login"}
                    </button>
                </div>

                {error && (
                    <p className="text-red-400 text-sm mt-4 text-center">
                        {error}
                    </p>
                )}

                <div className="mt-6 flex flex-wrap items-center justify-center gap-3">

                    <button
                        className={`${buttonBase} bg-slate-800 hover:bg-slate-700 text-cyan-400 min-w-[150px]`}
                        onClick={() =>
                            navigate(
                                "/register"
                            )
                        }
                    >
                        Create Account
                    </button>

                    <button
                        className={`${buttonBase} bg-slate-800 hover:bg-slate-700 text-slate-300 min-w-[120px]`}
                        onClick={() => {
                            setEmail("");
                            setPass("");
                            setError("");
                        }}
                    >
                        Clear
                    </button>

                </div>

            </motion.div>

        </div>
    );
}