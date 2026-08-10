import axios from "axios";

/*
|--------------------------------------------------------------------------
| CyberShield AI - Authentication Service
|--------------------------------------------------------------------------
*/

const API_URL = "http://127.0.0.1:5000";

/**
 * Login User
 */
export const loginUser = async (
    email,
    password
) => {

    try {

        const response = await axios.post(
            `${API_URL}/login`,
            {
                email,
                password
            }
        );

        return response.data;

    } catch (error) {

        return {
            success: false,
            message:
                error.response?.data?.message ||
                "Unable to connect to authentication server."
        };
    }
};

/**
 * Register User
 */
export const registerUser = async (
    username,
    email,
    password
) => {

    try {

        const response = await axios.post(
            `${API_URL}/register`,
            {
                username,
                email,
                password
            }
        );

        return response.data;

    } catch (error) {

        return {
            success: false,
            message:
                error.response?.data?.message ||
                "Unable to create account."
        };
    }
};

/**
 * Logout User
 */
export const logoutUser = () => {

    localStorage.removeItem("user");
    localStorage.removeItem("token");

    return {
        success: true
    };
};

/**
 * Get Current User
 */
export const getCurrentUser = () => {

    try {

        const user =
            localStorage.getItem("user");

        return user
            ? JSON.parse(user)
            : null;

    } catch {

        return null;
    }
};

/**
 * Check Authentication Status
 */
export const isAuthenticated = () => {

    return !!localStorage.getItem("user");
};