import express from 'express'
import argon2 from 'argon2';
import postgres from 'postgres';
import dotenv from 'dotenv';
import jwt from 'jsonwebtoken';
import cookieParser from 'cookie-parser';
// import { createClient } from '@supabase/supabase-js'
import multer from 'multer';
import paypal from '@paypal/checkout-server-sdk';

dotenv.config()
const clientId = process.env.PAYPAL_CLIENT_ID;
const clientSecret = process.env.PAYPAL_CLIENT_SECRET;
const app = express()
const connectionString = process.env.DATABASE_URL
const sql = postgres(connectionString)
const jwtSecret = process.env.JWT_SECRET
// const supabase = createClient(process.env.SUPABASE_PROJECT_URL, process.env.SUPABASE_API_KEY)
const upload = multer();

app.use(cookieParser())
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

const environment = new paypal.core.SandboxEnvironment(clientId, clientSecret);
const client = new paypal.core.PayPalHttpClient(environment);

async function jwt_verify(token) {
    try{
        const decoded=  await jwt.verify(token,jwtSecret)
        return decoded;
    }
    catch(err){
        return null;
    }
}

// async function uploadFile(file) {
//   const { data, error } = await supabase.storage.from('bucket_name').upload('file_path', file)
//   if (error) {
//     return false
//   } else {
//     return true
//   }
// }


function checkBlank(text){
    if(text===""){
        return null;
    }
    return text;
}

app.post("/auth/logout",async (req,res)=>{
    console.log("logout");
    res.clearCookie("token");
    return res.status(200).json({message:"success"});
})

app.post("/auth/register",upload.none(),async (req,res)=>{
    const token = req.cookies.token
    if(token){
        const decoded = await jwt_verify(token);
        if(decoded){
            return res.status(400).json({message:"Already login"});
        }
    }
    const data = req.body
    if(!data.name || typeof(data.name)!=="string" || data.name.length < 5 || data.name.length>20){
        return res.status(400).json({message:"Name invalid"});
    }
    if(!data.password || typeof(data.password)!=="string" || data.password.length < 5){
        return res.status(400).json({message:"password invalid"});
    }
    if(!data.email || typeof(data.email)!=="string" || data.email.length < 5 || data.email.length > 50 || data.email.search("@")==-1){
        return res.status(400).json({message:"email invalid"});
    }
    const hash_password = await argon2.hash(data.password);
    const existing_user = await sql`SELECT id from users where name = ${data.name} or email= ${data.email}`;
    if(existing_user.length>0){
        return res.status(400).json({message:"already have user with this name or email"});
    }

    const [new_user] = await sql`INSERT INTO users (name,password_hash,role,email) VALUES (${data.name},${hash_password},${"student"},${data.email}) RETURNING *`;
    const created_token = jwt.sign({
        id:new_user.id,
        role:new_user.role
    },jwtSecret,{expiresIn: "30d"});
    res.cookie('token',created_token);
    return res.json({message:"register complete"});
})

app.post("/auth/login",upload.none(),async (req,res)=>{
    const token = req.cookies.token
    if(token){
        const decoded = await jwt_verify(token);
        if(decoded){
            return res.status(400).json({message:"Already login"});
        }
    }
    const data = req.body
    if(!data.name || typeof(data.name)!=="string" || data.name.length < 5 || data.name.length>20){
        return res.status(400).json({message:"Name invalid"});
    }
    if(!data.password || typeof(data.password)!=="string" || data.password.length < 5){
        return res.status(400).json({message:"password invalid"});
    }
    const user_query = await sql`SELECT * FROM users WHERE deactive=false and (name = ${data.name} or email = ${data.name})`;
    if(user_query.length==0){
        return res.status(400).json({message:"no user"});
    }
    if(await argon2.verify(user_query[0].password_hash,data.password)){
        const created_token = jwt.sign({
            id:user_query[0].id,
            role:user_query[0].role
        },jwtSecret,{expiresIn: "30d"});
        res.cookie("token",created_token);
        return res.json({message:"login complete"});
    }
    return res.json({message:"wrong password"});
})

app.get("/users/me",upload.none(),async (req,res)=>{
    const token = req.cookies.token
    if(token){
        const decoded = await jwt_verify(token);
        if(decoded){
            const user_data = await sql`SELECT id,name,role,created_at,email,updated_at FROM users WHERE deactive=false and id = ${decoded.id}`;
            if(user_data.length==0){
                return res.status(400).json({message:"no user"});
            }
            return res.json(user_data[0]);
        }
        else{
            return res.status(400).json({message:"no data"});
        }
    }
    return res.status(400).json({message:"no data"});
})

app.get("/courses",async (req,res)=>{
    const category = req.query.category;
    const page = req.query.page || 1;
    if(category){
        const courses_data = await sql`SELECT * FROM courses WHERE category = ${category} AND deactive = false LIMIT 50 OFFSET ${(page-1)*50}`;
        return req.json({data:courses_data});
    }
    else{
        const courses_data = await sql`SELECT * FROM courses WHERE deactive=false LIMIT 50 OFFSET ${(page-1)*50}`;
        return req.json({data:courses_data});
    }
})

app.get("/courses/:id",async (req,res)=>{
    const id = req.params.id;
    const courses_data = await sql`SELECT * FROM courses WHERE deactive=false AND id=${id}`;
    if(courses_data.length==0){
        return req.status(400).json({message:"no data"});
    }
    return req.json(courses_data);
})

app.post("/courses",upload.none(),async (req,res)=>{
    const token = req.cookies.token
    if(token){
        const decoded = await jwt_verify(token);
        if(decoded){
            if(decoded.role!=="admin" && decoded.role!=="instructor"){
                return res.status(400).json({message:"No permission"});
            }
            const data = req.body;
            if(!data.title || typeof(data.title)!=="string" || data.title.length<3 || data.title.length>100){
                return res.status(400).json({message:"invalid title"});
            }
            if(!data.price || Number(data.price)<0){
                return res.status(400).json({message:"invalid price"});
            }
            const description = checkBlank(data.description);
            const category = checkBlank(data.category);
            const price  = data.price;
            const [new_courses] = await sql`INSERT INTO courses (title,description,category,price,instructor_id) VALUES (${data.title},${description},${category},${price},${decoded.id}) RETURNING *`;
            return res.json(new_courses);
        }
        else{
            return res.status(400).json({message:"Not login"});
        }
    }
    return res.status(400).json({message:"Not login"});
})

app.patch("/courses/:id",upload.none(),async (req,res)=>{
    const id = req.params.id;
    const token = req.cookies.token
    if(token){
        const decoded = await jwt_verify(token);
        if(decoded){
            if(decoded.role!=="admin" && decoded.role!=="instructor"){
                return res.status(400).json({message:"No permission"});
            }
            const data = req.body;
            const oldCoursesdata = await sql`SELECT * FROM courses WHERE id=${id} and deactive=false`;
            console.log(oldCoursesdata);
            if(oldCoursesdata.length==0){
                return res.status(400).json({message:"No courses"});
            }
            if(decoded.role!=="admin" && oldCoursesdata[0].instrcutor_id!=token.id){
                return res.status(400).json({message:"No permission"});
            }
            const [new_courses] = await sql`UPDATE courses SET title=${data.title||oldCoursesdata[0].title},description=${data.description||oldCoursesdata[0].description},
            category=${data.category||oldCoursesdata[0].category},price=${data.price||oldCoursesdata[0].price},updated_at=now() WHERE id=${id} RETURNING *`;
            return res.json(new_courses);
        }
        else{
            return res.status(400).json({message:"Not login"});
        }
    }
    return res.status(400).json({message:"Not login"});
})

app.delete("/courses/:id",upload.none(),async ()=>{
    const id = req.params.id;
    const token = req.cookies.token
    if(token){
        const decoded = await jwt_verify(token);
        if(decoded){
            if(decoded.role!=="admin" && decoded.role!=="instructor"){
                return res.status(400).json({message:"No permission"});
            }
            const data = req.body;
            const oldCoursesdata = await sql`SELECT * FROM courses WHERE id=${id} and deactive=false`;
            if(oldCoursesdata.length==0){
                return res.status(400).json({message:"No courses"});
            }
            if(decoded.role!=="admin" && oldCoursesdata[0].instrcutor_id!=token.id){
                return res.status(400).json({message:"No permission"});
            }
            await sql`UPDATE courses SET deactive=true,updated_at=now() WHERE id=${id}`;
            return res.status(200).json({message:"success"});
        }
        else{
            return res.status(400).json({message:"Not login"});
        }
    }
    return res.status(400).json({message:"Not login"});
})

app.post("/courses/:id/lessons",upload.none(),async(req,res)=>{
    const token = req.cookies.token;
    const id = req.params.id;
    if(token){
        const decoded = await jwt_verify(token);
        if(decoded){
            if(decoded.role!=="admin" && decoded.role!=="instructor"){
                return res.status(400).json({message:"No permission"});
            }
            const data = req.body;
            const oldCoursesdata = await sql`SELECT * FROM courses WHERE id=${id} and deactive=false`;
            if(oldCoursesdata.length==0){
                return res.status(400).json({message:"No courses"});
            }
            if(decoded.role!=="admin" && oldCoursesdata[0].instrcutor_id!=token.id){
                return res.status(400).json({message:"No permission"});
            }
            if(!data.title || typeof(data.title)!=="string" || data.title.length<3 || data.title.length>100){
                return res.status(400).json({message:"invalid title"});
            }
            const order_index = data.order_index | 0;
            const duration = checkBlank(data.duration);
            const [newCourses] = await sql`INSERT INTO lessons (course_id,title,order_index,duration,content_url) VALUES (${id},${title},${order_index},${duration},${data.content_url}) returning *`;
            return res.json(newCourses);
        }
        else{
            return res.status(400).json({message:"Not login"});
        }
    }
    return res.status(400).json({message:"Not login"});
})

app.get("/courses/:id/lessons",async (req,res)=>{
    const coursesId = req.params.id;
    const token = req.cookies.token;
    if(token){
        const decoded = await jwt_verify(token);
        if(decoded){
            const checkCourseEnrollment = await sql`SELECT * FROM enrollments WHERE course_id=${coursesId} AND  student_id=${decoded.id}`;
            if(checkCourseEnrollment.length==0){
                return res.status(400).json({message:"Not enroll yet"});
            }
            const data = await sql`SELECT * FROM lessons WHERE course_id=${coursesId}`;
            return res.json({data:data});
        }
        else{
            return res.status(400).json({message:"Not login"});
        }
    }
    
})

app.get("/courses/:id/reviews",upload.none(),async (req,res)=>{
    const coursesId = req.params.id;
    const reviews = await sql`SELECT * FROM reviews WHERE course_id = ${coursesId}`;
    return res.json({data:reviews});
})

app.post("/courses/:id/reviews",upload.none(),async (req,res)=>{
    const coursesId = req.params.id;
    const token = req.cookies.token;
    if(token){
        const decoded = await jwt_verify(token);
        if(decoded){
            const data = req.body;
            await sql`INSERT INTO reviews(course_id,student_id,rating,comment) VALUES (${coursesId},${decoded.id},${data.rating},${data.comment})`;
            return res.status(200).json({message:"success"});
        }
        else{
            return res.status(400).json({message:"Not login"});
        }
    }
    return res.status(400).json({message:"Not login"});
})

app.post("/courses/:id/enroll",async (req,res)=>{
    const coursesId = req.params.id;
    const token = req.cookies.token;
    if(token){
        const decoded = await jwt_verify(token);
        if(decoded){
            const checkenroll = await sql`SELECT * FROM enrollments WHERE course_id=${coursesId} AND student_id=${decoded.id}`;
            if(checkenroll.length>0){
                return res.status(400).json({message:"Already enroll"});
            }
            const courseData = await sql`SELECT * FROM courses WHERE id=${coursesId} AND deactive=false`;
            if(courseData.length==0){
                return res.status(400).json({message:"No course"});
            }
            const checkpayment = await sql`SELECT * FROM payments WHERE user_id=${decoded.id} AND course_id=${coursesId}`;
            let sumAmount = 0;
            for(let i = 0;i<checkpayment.length;i++){
                sumAmount+=checkpayment[i].amount;
            }
            if(sumAmount>=courseData[0].price){
                await sql`INSERT INTO enrollments (course_id,student_id) VALUES (${coursesId},${decoded.id})`;
                return res.status(200).json({message:"Successfully enroll"});
            }
        }
        else{
            return res.status(400).json({message:"Not login"});
        }
    }
    return res.status(400).json({message:"Not login"});
})

app.post("/users/me/enrollments",async (req,res)=>{
    const token = req.cookies.token;
    if(token){
        const decoded = await jwt_verify(token);
        if(decoded){
            const courses_enrolled  = await sql`SELECT en.course_id,en.progress,en.enrolled_at,co.title FROM enrollments AS en LEFT JOIN courses AS co ON le.id=en.course_id`;
            return res.json(courses_enrolled);
        }
        else{
            return res.status(400).json({message:"Not login"});
        }
    }
    return res.status(400).json({message:"Not login"});
})

app.post("/payments/checkout",async (req,res)=>{
    const token = req.cookies.token;
    if(!token){
        return res.status(400).json({message:"Not login"});
    }
    const decoded = await jwt_verify(token);
    if(!decoded){
        return res.status(400).json({message:"Not login"});
    }
    const { amount, currency, courseId } = req.body;

    const request = new paypal.orders.OrdersCreateRequest();
    request.prefer("return=representation");
    request.requestBody({
        intent: "CAPTURE",
        purchase_units: [
        {
            amount: {
            currency_code: currency, // e.g., "USD", "THB"
            value: amount
        }
        }
        ]
    });

    try {
        const order = await paypalClient.execute(request);
        await sql`INSERT INTO payments (user_id,course_id,amount,status,payment_gateway_id) VALUES (${decoded.id},${courseId},${amount},${"pending"},${order.result.id})`;
        res.status(200).json({ id: order.result.id });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: err.message });
    }
})

app.get("/payments/status/:id",async ()=>{
    const id = req.params.id;
    const token = req.cookies.token;
    if(token){
        const decoded = await jwt_verify(token);
        if(decoded){
            const courses_enrolled  = await sql`SELECT status FROM payments WHERE id=${id}`;
            return res.json({data:courses_enrolled});
        }
        else{
            return res.status(400).json({message:"Not login"});
        }
    }
    return res.status(400).json({message:"Not login"});
})

app.listen(3000,()=>console.log("running on http://localhost:3000/"))