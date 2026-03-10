const API="http://127.0.0.1:5000"


if(password.length < 6){
document.getElementById("registerResult").innerText="Password must be at least 6 characters"
return
}

if(!email.includes("@")){
document.getElementById("registerResult").innerText="Invalid email"
return
}


function login(){

let email=document.getElementById("email").value.trim()
let password=document.getElementById("password").value.trim()

if(email=="" || password==""){
document.getElementById("loginResult").innerText="Please enter email and password"
return
}

fetch(API+"/login",{
method:"POST",
headers:{
"Content-Type":"application/json"
},
body:JSON.stringify({
email:email,
password:password
})
})
.then(res=>res.json())
.then(data=>{

if(data.success){

localStorage.setItem("user",JSON.stringify(data.user))

window.location="index.html"

}else{

document.getElementById("loginResult").innerText=data.error

}

})
.catch(()=>{
document.getElementById("loginResult").innerText="Server error"
})

}

function scan(){

fetch(API+"/scan",{
method:"POST",
headers:{"Content-Type":"application/json"},
body:JSON.stringify({
features:[3,72,0,1,0,2,0,0,3,44,0]
})
})
.then(res=>res.json())
.then(data=>{
document.getElementById("result").innerText=
"Risk Level: "+data.risk_level+" | Score: "+data.score
})

}