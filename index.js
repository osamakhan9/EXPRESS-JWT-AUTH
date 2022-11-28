const express =  require('express')
const mongoose = require('mongoose')
const UserModel = require('./models/user.model')
const jwt = require('jsonwebtoken')
const argon2 = require('argon2')
const app = express()

app.use(express.urlencoded({ extended: true }));
app.use(express.json())

const blackList = []

const secret_KEY = "SECRET12345"
const refresh_KEY = "REFRESH12345"

app.get("/", (req,res)=>{
	res.send("Server Successfully")
})

app.post("/signup", async(req, res)=>{

	const {name, email, password, age, role}= req.body;

	const token = req.headers["authorization"]
	const hash = await argon2.hash(password)
	
	try{
		if(token){
			const decoded = jwt.decode(token)
			if(blackList.includes(token)){
				return res.status(404).send("token expired")
			}
			if(decoded.exp < new Date().getTime()){
				blackList.push(token)
				return res.status(403).send("token expired & add blacklist")
			}
			if(decoded){
				if(decoded.role == "HR"){
					const user = new UserModel({name, email,age, role:"Employee", password: hash})
				}
				await user.save()
				return res.status(200).send("Employee create successfully")
			}
		}
	}catch(e){
		return res.status(403).send("Your not HR, you are not allow to create employee")
	}

	const user = new UserModel({name, email, age, role, password:hash })
	await user.save()
	return res.status(201).send(`${role}successfully`)
	
})


app.post("/login", async(req, res)=>{

	const {email, password,}= req.body;
	const user = await UserModel.findOne({email})
	const hash = await argon2.hash(password)
	if(await argon2.verify(user.password, password)){
		
		const token = jwt.sign(
			{id: user._id, name: user.name, age: user.age, role:user.role},
			secret_KEY,
			{expiresIn : "5 mins"}
		)
		const reftoken = jwt.sign(
			{id: user._id, name: user.name, age: user.age, role:user.role},
			refresh_KEY,
			{expiresIn: "10 mins"}
		)
		
		return res.status(200).send({message: `${user.role}Login Success`, token,reftoken})
		}
	return res.status(401).send("Invalid Credentials")
})


app.get("/user/:id", async(req,res)=>{
	const {id} = req.params;
	const token = req.headers["authorization"]
	if(!token){
		return res.send("You need to login")
	}
	try{ 
        const verify = jwt.verify(token,secret_KEY)
		if(verify){
			const user = await UserModel.findById({_id: id});
			return res.send(user)
		}
	} catch (e){
		blackList.push(token)
		return res.send("token is expired ")
	}
})

app.post("/verify", async  (req,res)=>{

    const token = req.headers["authorization"]
    const reftoken = req.headers["refresh"]
 
    if(!token){
        return res.status(401).send("unAuthorized")
    }

    try{

        if(blackList.includes(reftoken)){
            return res.status(404).send("token is already expired")
        }

        const decoded = jwt.decode(token)
        let time_now = new Date().getTime()

        const Refreshdecoded = jwt.decode(reftoken)
        let Refreshtime_now = new Date().getTime()

        if(+time_now > decoded.exp  ){ 
            blackList.push(token)

            if(+Refreshtime_now > Refreshdecoded.exp  ){ 
                blackList.push(reftoken)
                return res.status(404).send("all token is expired")
            }

            const verify = jwt.verify(reftoken, refresh_KEY)
        
                 if(verify){
                
                  const Newtoken = jwt.sign(
                     { id: verify._id , name:verify.name, age:verify.age, role:verify.role }, 
                     secret_KEY ,
                     {expiresIn : "5 mins"}
                 )
                 return res.status(200).send( { message : `token Created` , Newtoken, reftoken  } )
            }
          
            return res.status(404).send("token is expired and added blackist")

        }else{
            return res.status(200).send("this is invalid")
        }

    }catch(e){
        return res.status(502).send("invalid")
    }
    

})

mongoose.connect("mongodb://localhost:27017/data").then((res)=>{
	app.listen(8080,()=>{
		console.log("server started on port 8080")
	})
})
