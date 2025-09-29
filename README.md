# Online Learning Platform Backend

Backend for an **Online Learning Platform**, built with **Node.js, Express, PostgreSQL, and Supabase Storage**. Handles **users, courses, lessons, enrollments, payments**, and allows **instructors to upload lesson files to Supabase buckets**.

---

## Features
- **User Management**: Roles for instructors and students
- **Courses & Lessons**: CRUD operations with PATCH support
- **Enrollments**: Track student progress
- **Payments**: Integration-ready for payment gateways
- **Reviews**: Students can leave ratings and comments
- **Secure API**: JWT authentication and role-based access control

---

## Tech Stack
- **Backend**: Node.js, Express
- **Database**: PostgreSQL (Postgres.js)
- **Authentication**: JWT (JSON Web Token)

---

## Getting Started

### 1. Clone the repository
```bash
git clone <your-repo-url>
cd online-learning-backend
```
### 2. Install dependencies
```bash
npm install
```
### 3. Environment Variables
```bash
JWT_SECRET=your_jwt_secret
DATABASE_URL=your_database_url
PAYPAL_CLIENT_ID=your_paypal_client_id
PAYPAL_CLIENT_SECRET=your_paypal_client_secret
```
### 4. Database Setup
```bash
create table users (
  id bigserial not null,
  name character varying(100) not null,
  password_hash character varying(255) not null,
  role character varying(20) not null,
  created_at timestamp without time zone null default now(),
  email text not null,
  updated_at timestamp without time zone null default now(),
  deactive boolean null default false,
  constraint users_pkey primary key (id),
  constraint users_email_key unique (email)
);
create table courses (
  id bigserial not null,
  title character varying(100) not null,
  description text null,
  category character varying(50) null,
  price integer null default 0,
  instructor_id bigint null,
  created_at timestamp without time zone null default now(),
  updated_at timestamp without time zone null default now(),
  deactive boolean null default false,
  constraint courses_pkey primary key (id),
  constraint courses_instructor_id_fkey foreign KEY (instructor_id) references users (id) on delete set null
);
create table lessons (
  id bigserial not null,
  course_id bigint null,
  title character varying(200) not null,
  order_index integer null,
  duration text null,
  created_at timestamp without time zone null default now(),
  updated_at timestamp without time zone null default now(),
  content_url text null,
  constraint lessons_pkey primary key (id),
  constraint lessons_course_id_fkey foreign KEY (course_id) references courses (id) on delete set null
);
create table enrollments (
  id bigserial not null,
  course_id bigint null,
  student_id bigint null,
  progress double precision null default 0,
  enrolled_at timestamp without time zone null default now(),
  constraint enrollments_pkey primary key (id),
  constraint enrollments_course_id_fkey foreign KEY (course_id) references courses (id) on delete set null,
  constraint enrollments_student_id_fkey foreign KEY (student_id) references users (id) on delete set null
);
create table payments (
  id bigserial not null,
  user_id bigint null,
  course_id bigint null,
  amount numeric(10, 2) null default 0,
  status character varying(20) null,
  payment_gateway_id character varying(100) not null,
  created_at timestamp without time zone null default now(),
  constraint payments_pkey primary key (id),
  constraint payments_course_id_fkey foreign KEY (course_id) references courses (id) on delete set null,
  constraint payments_user_id_fkey foreign KEY (user_id) references users (id) on delete set null
);
create table reviews (
  id bigserial not null,
  course_id bigint null,
  student_id bigint null,
  rating integer not null,
  comment text null,
  created_at timestamp without time zone null default now(),
  constraint reviews_pkey primary key (id),
  constraint reviews_course_id_fkey foreign KEY (course_id) references courses (id) on delete set null,
  constraint reviews_student_id_fkey foreign KEY (student_id) references users (id) on delete set null
);
```
### 5. Run the server
```bash
node index.js
```
---
## API Endpoints (Examples)

### Users
- `POST /users/register` → Register new user  
- `POST /users/login` → Authenticate and get JWT  

### Courses
- `GET /courses` → List all courses  
- `POST /courses` → Create a new course (instructor only)  
- `PATCH /courses/:id` → Update course details  

### Lessons
- `POST /courses/:courseId/lessons` → Add a lesson  
- `PATCH /lessons/:id` → Edit lesson info  
- `POST /lessons/:lessonId/upload` → Upload lesson file to Supabase bucket  

### Enrollments
- `POST /courses/:id/enroll` → Enroll a student  
- `GET /users/:id/enrollments` → Get student progress  

### Payments
- `POST /payments` → Create payment record  
- `GET /payments/:userId` → Get payment history  

### Reviews
- `POST /courses/:id/review` → Leave rating and comment  
- `GET /courses/:id/reviews` → List reviews for a course  
---
## Security

- **JWT authentication** for all protected routes  
- **Role-based access control** for instructors vs students  
- **File validation** (size/type) recommended before uploading
