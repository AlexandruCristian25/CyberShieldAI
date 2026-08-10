import { useState } from "react";
import { useNavigate } from "react-router-dom";
import { motion } from "framer-motion";
import { registerUser } from "../services/auth";
import logo from "../assets/cybershield-logo.png";

export default function Register() {

    const navigate = useNavigate();

    const [username, setUsername] = useState("");
    const [email, setEmail] = useState("");
    const [password, setPassword] = useState("");
    const [error, setError] = useState("");
    const [loading, setLoading] = useState(false);

    const smallButton =
        "text-white text-sm font-medium px-4 py-2 rounded-lg transition inline-flex items-center justify-center w-auto";

    const register = async () => {

        if (!username || !email || !password) {
            return setError(
                "All fields are required."
            );
        }

        if (username.length < 3) {
            return setError(
                "Username must contain at least 3 characters."
            );
        }

        const emailRegex =
            /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

        if (!emailRegex.test(email)) {
            return setError(
                "Please enter a valid email address."
            );
        }

        if (password.length < 8) {
            return setError(
                "Password must contain at least 8 characters."
            );
        }

        const passwordRegex =
            /^(?=.*[A-Z])(?=.*\d).{8,}$/;

        if (!passwordRegex.test(password)) {
            return setError(
                "Password must contain at least one uppercase letter and one number."
            );
        }

        try {
            setLoading(true);
            setError("");

            const result = await registerUser(
                username,
                email,
                password
            );

            if (result.success) {
                setUsername("");
                setEmail("");
                setPassword("");

                alert(
                    "Account created successfully"
                );

                navigate("/");
            }
            else {
                setError(
                    result.message ||
                    "Registration failed"
                );
            }

        } catch (err) {
            setError(
                err?.response?.data?.message ||
                "Unable to connect to server."
            );

        } finally {
            setLoading(false);
        }
    };

    return (
        <div className="min-h-screen flex items-center justify-center bg-gradient-to-br from-slate-950 via-slate-900 to-black text-white p-6">

            <motion.div
                initial={{
                    opacity: 0,
                    y: -20
                }}
                animate={{
                    opacity: 1,
                    y: 0
                }}
                transition={{
                    duration: 0.5
                }}
                className="w-full max-w-md rounded-3xl border border-purple-500/20 bg-slate-900/80 backdrop-blur-xl p-8 shadow-2xl"
            >

                <div className="flex justify-center items-center mb-2">
                    <img
                        src={logo}
                        alt="CyberShield AI Logo"
                        className="w-14 h-14 object-contain"
                    />
                </div>

                <h1
                    className="text-center text-4xl font-extrabold"
                    style={{
                        color: "#A970FF",
                        textShadow: "0 0 20px rgba(169,112,255,0.35)"
                    }}
                >
                    Create Account
                </h1>

                <p
                    className="text-center mt-2 mb-8"
                    style={{
                        color: "#B8B8D0"
                    }}
                >
                    Join CyberShield AI
                </p>

                <input
                    type="text"
                    name="cybershield_register_username"
                    placeholder="Username"
                    value={username}
                    autoComplete="off"
                    className="w-full mb-4 rounded-xl bg-slate-800 p-3 outline-none border border-slate-700 focus:border-purple-500"
                    onChange={(e) =>
                        setUsername(
                            e.target.value
                        )
                    }
                />

                <input
                    type="email"
                    name="cybershield_register_email"
                    placeholder="Email"
                    value={email}
                    autoComplete="new-email"
                    className="w-full mb-4 rounded-xl bg-slate-800 p-3 outline-none border border-slate-700 focus:border-purple-500"
                    onChange={(e) =>
                        setEmail(
                            e.target.value
                        )
                    }
                />

                <input
                    type="password"
                    name="cybershield_register_password"
                    placeholder="Password"
                    value={password}
                    autoComplete="new-password"
                    className="w-full mb-2 rounded-xl bg-slate-800 p-3 outline-none border border-slate-700 focus:border-purple-500"
                    onChange={(e) =>
                        setPassword(
                            e.target.value
                        )
                    }
                />

                <p className="text-xs text-slate-400 mb-4">
                    Password must contain at least 8 characters,
                    one uppercase letter and one number.
                </p>

                {error && (
                    <div className="mb-4 rounded-xl border border-red-500/30 bg-red-500/10 p-3">
                        <p className="text-red-400 text-sm">
                            {error}
                        </p>
                    </div>
                )}

                <div className="flex items-center justify-center gap-3 mt-2">

                    <button
                        onClick={register}
                        disabled={loading}
                        className={`${smallButton} bg-purple-600 hover:bg-purple-700 disabled:opacity-50`}
                    >
                        {loading
                            ? "Creating..."
                            : "Create Account"}
                    </button>

                    <button
                        onClick={() => {
                            setUsername("");
                            setEmail("");
                            setPassword("");
                            setError("");
                            navigate("/");
                        }}
                        className={`${smallButton} border border-slate-700 hover:bg-slate-800`}
                    >
                        Back to Login
                    </button>

                </div>

            </motion.div>

        </div>
    );
}