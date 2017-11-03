let express = require("express");
var cors = require("cors");
var mysql = require("mysql");
let app = express();
let bodyParser = require("body-parser");
var database = require("./db.js");
var bcrypt = require("bcrypt");
var dotenv = require("dotenv");
var jwt = require("jsonwebtoken");
let compression = require("compression");
let open = require("open");
let moment = require("moment");
let helmet = require("helmet");

dotenv.config();
app.use(helmet()); // Prevents XSS attacks
app.use(compression());
app.use(express.static("public"));
app.use(bodyParser({extended: true}));
app.use(cors());

var con;
function connection() {
    con = mysql.createConnection({
        host:'localhost',
        user:'root',
        password:'root123',
        database:'project'
    }); 
    con.connect(function(err) {
        if(err) throw err;
            console.log("Connected!");
    }); 
}

//user login
app.post("/api/login",function(req,res) {
    let {username,password}=req.body;
    res.writeHead(200,{"Content-Type": "application/json"});
    connection();
    con.query("select * from user where binary username=?",[username],function(err,results) {
        if(err) throw err;
        if(!results.length) {
            res.end(JSON.stringify({success:false, message:"User does not exist"}));
            return;
        }
        bcrypt.compare(password,results[0].password,(err,correct)=>{
            if(err) throw error;
            if(!correct) 
                res.end(JSON.stringify({success: false,message: "Username and password don't match"}));
            else {
                let user = {name: results[0].name, username: results[0].username};
                let token = jwt.sign(user, process.env.SESSION_SECRET, {
                    expiresIn: "1 day"
                });
                res.end(JSON.stringify({success: true, message: "Login success!", token}));
            }
        });
    });
});

//restaurant co-ordinator login
app.post("/api/rlogin",function(req,res) {
    let {username,password}=req.body;
    res.writeHead(200,{"Content-Type": "application/json"});
    connection();
    con.query("select * from restaurant where binary username=?",[username],function(err,results) {
        if(err) throw err;
        if(!results.length) {
            res.end(JSON.stringify({success:false, message:"User does not exist"}));
            return;
        }
        bcrypt.compare(password,results[0].password,(err,correct)=>{
            if(err) throw error;
            if(!correct) 
                res.end(JSON.stringify({success: false,message: "Username and password don't match"}));
            else {
                let user = {name: results[0].name, username: results[0].username};
                let token = jwt.sign(user, process.env.SESSION_SECRET, {
                    expiresIn: "1 day"
                });
                res.end(JSON.stringify({success: true, message: "Login success!", token}));
            }
                
        });
    });
});

//party hall co-ordinator login
app.post("/api/plogin",function(req,res) {
    let {username,password}=req.body;
    var correct,yes;
    res.writeHead(200,{"Content-Type": "application/json"});
    connection();
    con.query("select * from party where binary username=?",[username],function(err,results) {
        if(err) throw err;
        if(!results.length) {
            res.end(JSON.stringify({success:false, message:"User does not exist"}));
            return;
        }
        bcrypt.compare(password,results[0].password,(err,correct)=>{
            if(err) throw error;
            if(!correct) 
                res.end(JSON.stringify({success: false,message: "Username and password don't match"}));
            else {
                let user = {name: results[0].name, username: results[0].username};
                let token = jwt.sign(user, process.env.SESSION_SECRET, {
                    expiresIn: "1 day"
                });
                res.end(JSON.stringify({success: true, message: "Login success!", token}));
            }
                
        });
    });
});

//user registration
app.post("/api/signup",function(req,res) {
    let {name,username,password,email,choice1}=req.body;
    res.writeHead(200, {"Content-Type": "application/json"});
    connection();
    con.query("select * from user where binary username=?",[username],function(err,results) {
        if(err) throw err;
        if(results.length) { 
            res.end(JSON.stringify({success:false, message:"Username exists"}));
            return;
        }
    bcrypt.hash(password,10,(err,hash)=> {
        if(err) throw err;
        console.log(hash);
        con.query("insert into user values(?,?,?,?,?)",[username,hash,name,email,choice1],(err) => {
            if(err) {
               res.end(JSON.stringify({success:false, message:"Unknown error occurred.Try again."}));
            }
            res.end(JSON.stringify({success:true, message:"User registered successfully"}));
            });
        });
    });
});

//restaurant co-ordinator registration
app.post("/api/rsignup",function(req,res) {
    let {name,username,password,location,type,table}=req.body;
    res.writeHead(200, {"Content-Type": "application/json"});
    connection();
    con.query("select * from restaurant where binary username=?",[username],function(err,results) {
        if(err) throw err;
        if(results.length) { 
            res.end(JSON.stringify({success:false, message:"Username exists"}));
            return;
        }
    bcrypt.hash(password,10,(err,hash)=> {
        if(err) throw err;
        console.log(hash);
        con.query("insert into restaurant values(?,?,?,?,?,?)",[username,hash,name,location,type,table],(err) => {
            if(err) {
               res.end(JSON.stringify({success:false, message:"Unknown error occurred.Try again."}));
            }
            res.end(JSON.stringify({success:true, message:"Registered successfully"}));
            });
        });
    });
});

//party hall co-ordinator registration
app.post("/api/psignup",function(req,res) {
    let {name,username,password,location,amount}=req.body;
    res.writeHead(200, {"Content-Type": "application/json"});
    connection();
    con.query("select * from party where binary username=?",[username],function(err,results) {
        if(err) throw err;
        if(results.length) { 
            res.end(JSON.stringify({success:false, message:"Username exists"}));
            return;
        }
    bcrypt.hash(password,10,(err,hash)=> {
        if(err) throw err;
        console.log(hash);
        con.query("insert into party values(?,?,?,?,?)",[username,hash,name,location,amount],(err) => {
            if(err) {
               res.end(JSON.stringify({success:false, message:"Unknown error occurred.Try again."}));
            }
            res.end(JSON.stringify({success:true, message:"Registered successfully"}));
            });
        });
    });
});

//search restaurants 
app.post("/api/search",function(req,res) {
    let {type} = req.body;
    res.writeHead(200, {"Content-Type": "application/json"});
    console.log(type);
    connection();
    con.query("select name,location from restaurant where type=?",[type],function(err,rows,fields) {
        if(err) throw err;
        if (!rows.length) {
            res.end(JSON.stringify({success:false, resto:"No restaurants"}));
            return;
        }
        console.log(rows);
        res.end(JSON.stringify({success: true, resto: rows}));
    }); 
     con.end();
});

//view reviews
app.get("/api/review",function(req,res) {
    res.writeHead(200, {"Content-Type": "application/json"});
    connection();
    con.query("select u.name as user,r.name as resto,comment,rating from user u,restaurant r,review r1 where u.username=r1.user and r.username=r1.ruser",function(err,rows,fields) {
        if(err) throw err;
        if (!rows.length) {
            res.end(JSON.stringify({success:false, rev:"No reviews added yet"}));
            return;
        }
        console.log(rows);
        res.end(JSON.stringify({success: true, rev: rows}));
    }); 
    con.end();
});

//search party halls
app.post("/api/psearch",function(req,res) { 
    let {choice} = req.body;
    res.writeHead(200, {"Content-Type": "application/json"});
    console.log(choice);
    connection(); 
    switch(choice) {
    case "1": con.query("select name,location,amount from party where amount<50000",function(err,rows,fields) {
            if(err) throw err;
            if (!rows.length) {
                res.end(JSON.stringify({success:false, par:"No party halls"}));
                return;
            }
            console.log(rows);
            res.end(JSON.stringify({success: true, par: rows}));
            }); 
            con.end();
            break;
    case "2": con.query("select name,location,amount from party where amount between 50000 and 100000",function(err,rows,fields) {
            if(err) throw err;
            if (!rows.length) {
                res.end(JSON.stringify({success:false, par:"No party halls"}));
                return;
            }
            console.log(rows);
            res.end(JSON.stringify({success: true, par: rows}));
            }); 
            con.end();
            break;
    case "3": con.query("select name,location,amount from party where amount between 100000 and 300000",function(err,rows,fields) {
            if(err) throw err;
            if (!rows.length) {
                res.end(JSON.stringify({success:false, par:"No party halls"}));
                return;
            }
            console.log(rows);
            res.end(JSON.stringify({success: true, par: rows}));
            }); 
            con.end();
            break;
    case "4":
            con.query("select name,location,amount from party where amount>300000",function(err,rows,fields) {
            if(err) throw err;
            if (!rows.length) {
                res.end(JSON.stringify({success:false, par:"No party halls"}));
                return;
            }
            console.log(rows);
            res.end(JSON.stringify({success: true, par: rows}));
            }); 
            con.end();
            break;
    }
});

//user details
app.post("/api/whoami",function(req,res) {
    res.writeHead(200, {"Content-Type": "application/json"});
    let {token} = req.body;
    console.log(token);
    jwt.verify(token, process.env.SESSION_SECRET, (err, decoded) => {
        console.log(decoded);
        if (err)
            res.end(JSON.stringify({success: false}));
        else {
            console.log(decoded);
            res.end(JSON.stringify({success: true, user: decoded}));
        }
    });
});

//view table reservations
app.post("/api/viewRes",function(req,res) {
    res.writeHead(200,{"Content-Type": "application/json"});
    let {username} = req.body;
    connection();
    let date = new Date().toISOString();
    console.log(date);
    con.query("select u.name as name,tables,code,d,t from reservation r,user u where r.username=u.username and ruser=? and datediff(now(),d)=0",[username],function(err,row,fields){
        if(err) throw err;
        if(!row.length)
            res.end(JSON.stringify({success: false, reserve: "No reservations made yet"}));
        else    
            res.end(JSON.stringify({success: true, reserve: row}));
    });
});

//add offers
app.post("/api/add_offers",function(req,res) {
    res.writeHead(200,{"Content-Type": "application/json"});
    let {username,offer,promo} = req.body;
    connection();
    con.query("select * from offers where code=?",[promo],function(err,rows,fields){
        if(err) throw err;
        if(rows.length) {
            res.end(JSON.stringify({success:false, message:"Promo code has been used. Try again!"}));
            return;
        }
    });
    con.query("insert into offers values(?,?,?)",[username,offer,promo],(err,result)=>{
        if(err) 
            res.end(JSON.stringify({success:false, message:"Unknown error occurred. Try again!"}));
        else    
            res.end(JSON.stringify({success:true, message: "Offer has been added successfully!"}));
    });
});

//delete offers
app.post("/api/delete_offers",function(req,res) {
    res.writeHead(200,{"Content-Type": "application/json"});
    let {username,dpromo} = req.body;
    connection();
    con.query("select * from offers where code=?",[dpromo],function(err,rows,fields){
        if(err) throw err;
        if(!rows.length) {
            res.end(JSON.stringify({success:false, message:"No offer with this promo exists"}));
            return;
        }
    });
    con.query("delete from offers where ruser=? and code=?",[username,dpromo],(err,result)=>{
        if(err) throw err;
        else  
            res.end(JSON.stringify({success:true, message: "Offer has been deleted successfully!"}));
    });
});

//view party hall reservations
app.post("/api/reserve",function(req,res) {
    res.writeHead(200,{"Content-Type": "application/json"});
    let {username} = req.body;
    connection();
    let date = new Date().toISOString();
    console.log(date);
    con.query("select u.name as name,d,t from p_reserve r,user u where r.username=u.username and puser=? and datediff(now(),d)=0",[username],function(err,row,fields){
        if(err) throw err;
        if(!row.length)
            res.end(JSON.stringify({success: false, reserve: "No reservations made yet"}));
        else    
            res.end(JSON.stringify({success: true, reserve: row}));
    });
});

//view offers
app.get("/api/view_offers",function(req,res) {
    res.writeHead(200,{"Content-Type": "application/json"});
    connection();
    con.query("select * from offers",function(err,row,fields){
        if(err) throw err;
        if(!row.length)
            res.send(JSON.stringify({success:false, view:"No offers have been added yet"}));
        else
            res.end(JSON.stringify({success:true, view: row}));
    });
});

//add reviews
app.post("/api/add_review",function(req,res){
    res.writeHead(200,{"Content-Type":"application/json"});
    let {username,resto,comment,rating,location} = req.body;
    connection();
    let ruser;
    con.query("select * from restaurant where name=? and location=?",[resto,location],function(err,row,fields){
        if(err) throw err;
        if(!row.length) {
            res.end(JSON.stringify({success:false, message:"Error in the details of restaurant"}));
            return;
        }
        else {
            ruser = row[0].username;
            console.log(ruser);
            con.query("insert into review values(?,?,?,?)",[username,ruser,comment,rating],function(err,result){
                if(err) 
                    res.end(JSON.stringify({success:false, message:"Unknown error occurred. Try again."}));
                else
                    res.end(JSON.stringify({success:true, message:"Review has been added successfully!"}));
            });
        }
    });
});

//table booking
app.post("/api/tbook",function(req,res){
    res.writeHead(200,{"Content-Type":"application/json"});
    let {username,restaurant,date,time,tables,promo} = req.body;
    let fdate = new Date(dateṭ); 
    console.log(date);
    console.log(fdate);
    console.log(moment(time, "h:m A").format("H:M"));
    connection();
    
});

app.listen(8080, (err, res) => {
    open("http://localhost:8080/restaurant.html");
});