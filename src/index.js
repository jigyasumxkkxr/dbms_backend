const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { PrismaClient } = require('@prisma/client');
const cors = require('cors');
require('dotenv').config();

const app = express();
const prisma = new PrismaClient();

app.use(cors());
app.use(express.json());

const SECRET_KEY = process.env.SECRET_KEY || 'your_secret_key';

// Middleware for role-based authentication
function authenticateRole(roles) {
  return async (req, res, next) => {
    const token = req.headers['authorization']?.split(' ')[1];
    if (!token) return res.status(401).json({ message: 'Unauthorized' });

    try {
      const decoded = jwt.verify(token, SECRET_KEY);
      const user = await prisma.user.findUnique({ where: { id: decoded.id } });
      if (!user || !roles.includes(user.role)) {
        return res.status(403).json({ message: 'Forbidden' });
      }
      req.user = user;
      next();
    } catch (error) {
      return res.status(401).json({ message: 'Unauthorized' });
    }
  };
}

// Routes

app.post('/register', async (req, res) => {
  const { name, email, password, role } = req.body;

  try {
    // Validate required fields
    if (!name || !email || !password || !role) {
      return res.status(400).json({ error: 'All fields are required' });
    }

    // Validate role
    const validRoles = ['STUDENT', 'TEACHER', 'ADMIN'];
    if (!validRoles.includes(role)) {
      return res.status(400).json({ error: 'Invalid role' });
    }

    // Check if the user already exists
    const existingUser = await prisma.user.findUnique({
      where: { email },
    });
    if (existingUser) {
      return res.status(400).json({ error: 'User already exists' });
    }

    // Hash password
    const hashedPassword = await bcrypt.hash(password, 10);

    // Create user
    const user = await prisma.user.create({
      data: {
        name,
        email,
        password: hashedPassword,
        role,
      },
    });

    // Respond with success
    res.status(201).json({ message: 'User registered successfully', user });
  } catch (error) {
    console.error('Error in /register:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});


app.post('/login', async (req, res) => {
  const { email, password } = req.body;

  try {
    const user = await prisma.user.findUnique({ where: { email } });
    if (!user || !(await bcrypt.compare(password, user.password))) {
      return res.status(401).json({ message: 'Invalid credentials' });
    }

    const token = jwt.sign({ id: user.id }, SECRET_KEY, { expiresIn: '1d' });
    res.json({ token, user });
  } catch (error) {
    res.status(500).json({ error: 'Something went wrong' });
  }
});

app.get('/teachers', async (req, res) => {
  try {
    const teachers = await prisma.user.findMany({
      where: { role: 'TEACHER' },
      select: { id: true, name: true, email: true }, // Minimal data
    });
    res.status(200).json(teachers);
  } catch (error) {
    console.error("Error fetching teachers:", error);
    res.status(500).json({ error: "Failed to fetch teachers" });
  }
});


app.post('/admin/course', authenticateRole(['ADMIN']), async (req, res) => {
  const { title, description, teacherId } = req.body;

  // Ensure teacherId is an integer
  const teacherIdParsed = parseInt(teacherId, 10);

  if (isNaN(teacherIdParsed)) {
    return res.status(400).json({ error: 'Invalid teacherId' });
  }

  try {
    const course = await prisma.course.create({
      data: { title, description, teacherId: teacherIdParsed },
    });
    res.status(201).json({ message: 'Course created', course });
  } catch (error) {
    console.error(error); // Log error for more details
    res.status(400).json({ error: 'Error creating course' });
  }
});

app.get('/admin/courses', authenticateRole(['ADMIN']), async (req, res) => {
  try {
    const courses = await prisma.course.findMany({
      include: {
        teacher: true, // Include teacher data
        students: true, // Optionally include students, if needed
      },
    });
    res.status(200).json(courses);
  } catch (error) {
    console.error(error);
    res.status(400).json({ error: 'Error fetching courses' });
  }
});

app.put('/admin/course/:id', authenticateRole(['ADMIN']), async (req, res) => {
  const { title, description, teacherId } = req.body;
  const courseId = parseInt(req.params.id, 10);

  if (isNaN(courseId)) {
    return res.status(400).json({ error: 'Invalid course ID' });
  }

  try {
    const updatedCourse = await prisma.course.update({
      where: { id: courseId },
      data: { title, description, teacherId : parseInt(teacherId, 10) },
    });
    res.status(200).json({ message: 'Course updated successfully', updatedCourse });
  } catch (error) {
    console.error(error);
    res.status(400).json({ error: 'Error updating course' });
  }
});

// DELETE course for admin
app.delete('/admin/course/:id', authenticateRole(['ADMIN']), async (req, res) => {
  const courseId = parseInt(req.params.id, 10);

  if (isNaN(courseId)) {
    return res.status(400).json({ error: 'Invalid course ID' });
  }

  try {
    // Delete the course
    await prisma.course.delete({
      where: { id: courseId },
    });
    res.status(200).json({ message: 'Course deleted successfully' });
  } catch (error) {
    console.error(error);
    res.status(400).json({ error: 'Error deleting course' });
  }
});


app.post('/student/course', authenticateRole(['STUDENT']), async (req, res) => {
  const { courseId } = req.body;
  const studentId = req.user.id;

  try {
    await prisma.course.update({
      where: { id: courseId },
      data: { students: { connect: { id: studentId } } },
    });
    res.json({ message: 'Enrolled in course' });
  } catch (error) {
    res.status(400).json({ error: 'Error enrolling in course' });
  }
});

app.delete('/student/course/:courseId', authenticateRole(['STUDENT']), async (req, res) => {
  const { courseId } = req.params;
  const studentId = req.user.id;

  try {
    await prisma.course.update({
      where: { id: parseInt(courseId) },
      data: { students: { disconnect: { id: studentId } } },
    });
    res.json({ message: 'Successfully de-enrolled from course' });
  } catch (error) {
    res.status(400).json({ error: 'Error de-enrolling from course' });
  }
});

app.get('/student/courses', authenticateRole(['STUDENT']), async (req, res) => {
  const studentId = req.user.id;

  try {
    const courses = await prisma.course.findMany({
      where: {
        students: {
          some: { id: studentId },
        },
      },
      include: {
        grades: true, // Including grade information for each course
      },
    });

    const enrolledCourses = courses.map((course) => {
      const grade = course.grades.find(
        (grade) => grade.studentId === studentId
      );
      return {
        ...course,
        grade: grade ? grade.value : null,
      };
    });

    res.json(enrolledCourses);
  } catch (error) {
    res.status(400).json({ error: 'Error fetching enrolled courses' });
  }
});

app.get('/courses', authenticateRole(['STUDENT', 'ADMIN', 'TEACHER']), async (req, res) => {
  try {
    const courses = await prisma.course.findMany({
      include: {
        teacher: true, // Teacher information
      },
    });
    res.status(200).json(courses);
  } catch (error) {
    res.status(400).json({ error: 'Error fetching available courses' });
  }
});

// Get courses assigned to teacher
app.get('/teacher/courses', authenticateRole(['TEACHER']), async (req, res) => {
  const teacherId = req.user.id;
  
  try {
    const courses = await prisma.course.findMany({
      where: { teacherId },
      include: {
        teacher: true, // Include teacher details
        students: true, // Include students enrolled in the course
      },
    });
    res.json(courses);
  } catch (error) {
    console.error(error);
    res.status(400).json({ error: 'Error fetching courses' });
  }
});

// Get enrolled students for a specific course
app.get('/teacher/course/:courseId/students', authenticateRole(['TEACHER']), async (req, res) => {
  const { courseId } = req.params;
  
  try {
    const course = await prisma.course.findUnique({
      where: { id: parseInt(courseId) },
      include: {
        students: true, // Get the students enrolled in this course
      },
    });

    if (!course) {
      return res.status(404).json({ error: 'Course not found' });
    }

    res.json(course.students);
  } catch (error) {
    console.error(error);
    res.status(400).json({ error: 'Error fetching students for the course' });
  }
});



app.post('/teacher/course/:courseId/student/:studentId/grade', authenticateRole(['TEACHER']), async (req, res) => {
  const { courseId, studentId } = req.params;
  const { grade } = req.body; // Teacher assigns numeric marks

  try {
    // Check if the course exists
    const course = await prisma.course.findUnique({
      where: { id: parseInt(courseId) },
      include: { students: true },
    });

    if (!course) {
      return res.status(404).json({ error: 'Course not found' });
    }

    // Check if the student is enrolled in the course
    const studentExists = course.students.some(student => student.id === parseInt(studentId));
    if (!studentExists) {
      return res.status(404).json({ error: 'Student not enrolled in this course' });
    }

    // Check if grade already exists for the student in this course
    const existingGrade = await prisma.grade.findFirst({
      where: {
        studentId: parseInt(studentId),
        courseId: parseInt(courseId),
      },
    });

    if (existingGrade) {
      // Update existing grade
      await prisma.grade.update({
        where: { id: existingGrade.id },
        data: { marks: grade }, // Store the numeric mark
      });
    } else {
      // Create a new grade entry for the student and course
      await prisma.grade.create({
        data: {
          marks: grade, // Store numeric marks
          courseId: parseInt(courseId),
          studentId: parseInt(studentId),
        },
      });
    }

    res.json({ message: 'Grade assigned successfully' });
  } catch (error) {
    console.error(error);
    res.status(400).json({ error: 'Error assigning grade' });
  }
});


app.get('/student/course/:courseId/grade', authenticateRole(['STUDENT']), async (req, res) => {
  const { courseId } = req.params;
  const { studentId } = req.user; // Assuming you're getting the student ID from the authenticated user

  try {
    // Get the grade for the student in this course
    const grade = await prisma.grade.findFirst({
      where: {
        studentId: parseInt(studentId),
        courseId: parseInt(courseId),
      },
    });

    if (!grade) {
      return res.status(404).json({ error: 'Grade not found for this student in the course' });
    }

    // Convert numeric marks to letter grade
    const letterGrade = convertMarksToGrade(grade.marks);

    res.json({ marks: grade.marks, grade: letterGrade }); // Return both numeric marks and letter grade
  } catch (error) {
    console.error(error);
    res.status(400).json({ error: 'Error fetching grade' });
  }
});

// Helper function to convert numeric marks to letter grade
function convertMarksToGrade(marks) {
  if (marks >= 90) return 'A';
  if (marks >= 80) return 'B';
  if (marks >= 70) return 'C';
  if (marks >= 60) return 'D';
  return 'F'; // For marks less than 60
}


const PORT = process.env.PORT || 4000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
