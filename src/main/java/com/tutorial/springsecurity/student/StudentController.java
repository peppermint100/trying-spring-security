package com.tutorial.springsecurity.student;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Arrays;
import java.util.List;

@RestController
@RequestMapping("api/v1/students")
public class StudentController {

    // Arrays.asList => convert all the elements in array into a whole package of a List
    private static final List<Student> STUDENTS = Arrays.asList(
            new Student(1, "Pepper"),
            new Student(2, "Kelly"),
            new Student(3, "Noel")
    );

    @GetMapping(path="{studentId}")
    public Student getStudent(@PathVariable("studentId") Integer studentId){
        return STUDENTS.stream().filter(student -> studentId.equals(student.getStudentId()))
                .findFirst()
                .orElseThrow(()->new IllegalStateException("Student " + studentId + "does not exist"));
    }
}
