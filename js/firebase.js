// js/firebase.js

import { initializeApp } from "https://www.gstatic.com/firebasejs/10.8.0/firebase-app.js";
import { getAuth } from "https://www.gstatic.com/firebasejs/10.8.0/firebase-auth.js";
import { getFirestore } from "https://www.gstatic.com/firebasejs/10.8.0/firebase-firestore.js";
import { getStorage } from "https://www.gstatic.com/firebasejs/10.8.0/firebase-storage.js";

// 🔥 REPLACE WITH YOUR OWN FIREBASE CONFIG
const firebaseConfig = {
   apiKey: "AIzaSyA-z1Zx-0qAj6_FGiclcXFdIjiKSjXlUKw",
    authDomain: "sevasphere-6dce7.firebaseapp.com",
    projectId: "sevasphere-6dce7",
    storageBucket: "sevasphere-6dce7.firebasestorage.app",
    messagingSenderId: "930986469572",
    appId: "1:930986469572:web:7c62c3e6ff7c3f90d98191",
    measurementId: "G-KR6K2EKCW6"
};

// Initialize Firebase
const app = initializeApp(firebaseConfig);

// Services
const auth = getAuth(app);
const db = getFirestore(app);
const storage = getStorage(app);

// Collection Names
const COLLECTIONS = {
    USERS: "users",
    EVENTS: "events",
    REGISTRATIONS: "registrations",
    NOTIFICATIONS: "notifications",
    UPLOADS: "uploads"
};

export { app, auth, db, storage, COLLECTIONS };
