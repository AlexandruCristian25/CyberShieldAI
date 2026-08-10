import {
    BrowserRouter,
    Routes,
    Route,
    Navigate
} from "react-router-dom";

import Login from "./pages/Login";
import Register from "./pages/Register";
import Dashboard from "./pages/Dashboard";
import Admin from "./pages/Admin";

function ProtectedRoute({ children }) {

    const user = localStorage.getItem("user");

    if (!user) {
        return <Navigate to="/" replace />;
    }

    return children;
}

function AdminRoute({ children }) {

    const user = JSON.parse(
        localStorage.getItem("user")
    );

    if (!user) {
        return <Navigate to="/" replace />;
    }

    if (user.role !== "admin") {
        return <Navigate to="/dashboard" replace />;
    }

    return children;
}

function App() {

    return (
        <BrowserRouter>
            <Routes>

                <Route
                    path="/"
                    element={<Login />}
                />

                <Route
                    path="/register"
                    element={<Register />}
                />

                <Route
                    path="/dashboard"
                    element={
                        <ProtectedRoute>
                            <Dashboard />
                        </ProtectedRoute>
                    }
                />

                <Route
                    path="/admin"
                    element={
                        <AdminRoute>
                            <Admin />
                        </AdminRoute>
                    }
                />

            </Routes>
        </BrowserRouter>
    );
}

export default App;