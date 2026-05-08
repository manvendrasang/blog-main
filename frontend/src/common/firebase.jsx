import { GoogleAuthProvider, getAuth, signInWithPopup } from 'firebase/auth';
import { initializeApp } from "firebase/app";

const firebaseConfig = {
  apiKey: "AIzaSyDMNx6NAukbBl7lj7v1ND0pW55FXON8wRQ",
  authDomain: "blog-space-20004.firebaseapp.com",
  projectId: "blog-space-20004",
  storageBucket: "blog-space-20004.firebasestorage.app",
  messagingSenderId: "492102521560",
  appId: "1:492102521560:web:a3586977cb5d8de4a5bdad"
};

// Initialize Firebase
const app = initializeApp(firebaseConfig);

const provider = new GoogleAuthProvider();
const auth = getAuth();

export const authWithGoogle = async () => {
    let user = null;
    await signInWithPopup(auth, provider).then((result)=>{
        user = result.user
    }).catch((err) => {
        console.log(err)
    })
    return user;
}