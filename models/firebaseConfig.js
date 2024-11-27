// firebaseConfig.js
import { initializeApp } from "firebase/app";
import { getFirestore } from "firebase/firestore";
import { getStorage } from "firebase/storage"; // Adicionado
import 'dotenv/config';

const firebaseConfig = {
  apiKey: "AIzaSyBNIaO0le5Mn4UDxWX32YDoY_b4xNZikDg",
  authDomain: "reactfirebase-140c5.firebaseapp.com",
  projectId: "reactfirebase-140c5",
  storageBucket: "reactfirebase-140c5.appspot.com",
  messagingSenderId: "1072804392777",
  appId: "1:1072804392777:web:03c3269e8d6615d2563498",
  measurementId: "G-VRM6H5BV4Y"
};

const firebaseApp = initializeApp(firebaseConfig);
const db = getFirestore(firebaseApp);
const storage = getStorage(firebaseApp); 

export { db, storage }; // Exportar storage
