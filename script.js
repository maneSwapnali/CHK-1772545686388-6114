const API="http://127.0.0.1:5000"


function register(){

fetch(API+"/register",{
method:"POST",
headers:{"Content-Type":"application/json"},
body:JSON.stringify({
name:document.getElementById("name").value,
email:document.getElementById("email").value,
password:document.getElementById("password").value,
age_group:document.getElementById("age").value,
vulnerability_group:document.getElementById("group").value
})
})
.then(res=>res.json())
.then(data=>{
document.getElementById("registerResult").innerText=data.message
})

}


function login(){

fetch(API+"/login",{
method:"POST",
headers:{"Content-Type":"application/json"},
body:JSON.stringify({
email:document.getElementById("email").value,
password:document.getElementById("password").value
})
})
.then(res=>res.json())
.then(data=>{
if(data.success){
window.location="index.html"
}else{
document.getElementById("loginResult").innerText="Login Failed"
}
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

