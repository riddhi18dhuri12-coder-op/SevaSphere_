// js/auth.js

import { auth, db, COLLECTIONS } from "./firebase.js";

import {
    createUserWithEmailAndPassword,
    signInWithEmailAndPassword,
    signOut,
    onAuthStateChanged
} from "https://www.gstatic.com/firebasejs/10.8.0/firebase-auth.js";

import {
    doc,
    setDoc,
    getDoc
} from "https://www.gstatic.com/firebasejs/10.8.0/firebase-firestore.js";

/* ===========================
   SIGNUP - ADMIN
=========================== */
export async function adminSignup(name, email, password) {
    try {
        const userCredential = await createUserWithEmailAndPassword(auth, email, password);
        const user = userCredential.user;

        await setDoc(doc(db, COLLECTIONS.USERS, user.uid), {
            name: name,
            email: email,
            role: "admin",
            createdAt: new Date()
        });

        return { success: true, user };
    } catch (error) {
        return { success: false, error: error.message };
    }
}

/* ===========================
   SIGNUP - VOLUNTEER
=========================== */
export async function volunteerSignup(name, email, password) {
    try {
        const userCredential = await createUserWithEmailAndPassword(auth, email, password);
        const user = userCredential.user;

        await setDoc(doc(db, COLLECTIONS.USERS, user.uid), {
            name: name,
            email: email,
            role: "volunteer",
            createdAt: new Date()
        });

        return { success: true, user };
    } catch (error) {
        return { success: false, error: error.message };
    }
}

/* ===========================
   LOGIN
=========================== */
export async function login(email, password) {
    try {
        const userCredential = await signInWithEmailAndPassword(auth, email, password);
        const user = userCredential.user;

        const userDoc = await getDoc(doc(db, COLLECTIONS.USERS, user.uid));

        if (!userDoc.exists()) {
            await signOut(auth);
            return { success: false, error: "User data not found." };
        }

        const userData = userDoc.data();

        return {
            success: true,
            user: {
                uid: user.uid,
                name: userData.name,
                role: userData.role
            }
        };
    } catch (error) {
        return { success: false, error: error.message };
    }
}

/* ===========================
   LOGOUT
=========================== */
export async function logout() {
    try {
        await signOut(auth);
        return { success: true };
    } catch (error) {
        return { success: false, error: error.message };
    }
}

/* ===========================
   CHECK AUTH
=========================== */
export function checkAuth(callback) {
    onAuthStateChanged(auth, async (user) => {
        if (user) {
            const userDoc = await getDoc(doc(db, COLLECTIONS.USERS, user.uid));
            if (userDoc.exists()) {
                callback({
                    uid: user.uid,
                    ...userDoc.data()
                });
            } else {
                callback(null);
            }
        } else {
            callback(null);
        }
    });
}

/* ===========================
   PROTECT PAGE
=========================== */
export function protectPage(requiredRole) {
    checkAuth((user) => {
        if (!user) {
            window.location.href =
                requiredRole === "admin"
                    ? "../admin/admin-login.html"
                    : "../volunteer/volunteer-login.html";
        } else if (requiredRole && user.role !== requiredRole) {
            if (user.role === "admin") {
                window.location.href = "../admin/admin-dashboard.html";
            } else {
                window.location.href = "../volunteer/volunteer-dashboard.html";
            }
        }
    });
}

/* ===========================
   REDIRECT BY ROLE
=========================== */
export function redirectByRole(role) {

    if (role === "admin") {
        window.location.href = "/admin/admin-dashboard.html";
    } 
    else if (role === "volunteer") {
        window.location.href = "/volunteer/volunteer-dashboard.html";
    } 
    else {
        window.location.href = "/index.html";
    }
}
