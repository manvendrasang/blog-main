# blog-main

go to firebase > create project > add nickname > add firebase code to frontend/src/common/firebase.jsx > then on firbase goto build > Authentication > get started > add provider > choose google > select email > save > then in firebase.jsx paste the below code >>

import { GoogleAuthProvider, getAuth } from 'firebase/auth';
const provider = new GoogleAuthProvider;
const auth = getAuth();
export const authWithGoogle = async () => {
    let user = null;
    await signInWithPopup(auth, provider).then((resul)=>{
        user = result.user
    }).catch((err) => {
        console.log(err)
    })
    return user;
}

after this goto frontend/src/pages/userAuthForm.jsx > find the "Continue with Google" button and add the following onclick function in the button attribute
onclick={handleGoogleAuth} and just above the return statement in the same file add the following code >>

import { authWithGoogle } from "../common/firebase"
const handleGoogleAuth = (e) = {
    e.preventDefault();
    authWithGoogle().then(user => {
        console.log(user);
    }).catch(err => {
        toast.error('trouble logging in with google');
        console.log(err)
    })
}