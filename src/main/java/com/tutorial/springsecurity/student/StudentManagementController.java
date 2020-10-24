package com.tutorial.springsecurity.student;

import org.springframework.web.bind.annotation.*;

import java.util.Arrays;
import java.util.List;

@RestController
@RequestMapping("management/api/v1/students")
public class StudentManagementController {
    // Arrays.asList => convert all the elements in array into a whole package of a List
    private static final List<Student> STUDENTS = Arrays.asList(
            new Student(1, "Pepper"),
            new Student(2, "Kelly"),
            new Student(3, "Noel")
    );

    @GetMapping
    public List<Student> getAllStudents(){
        return STUDENTS;
    }

    @PostMapping
    public void registerStudent(@RequestBody Student student){
        System.out.println("student has registerd");
        System.out.println(student);
    }

    @DeleteMapping(path="{studentId}")
    public void deleteStudent(@PathVariable("studentId") Integer studentId){
        System.out.println("student has deleted");
        System.out.println(studentId);
    }

    @PutMapping(path="{studentId}")
    public void updateStudent(@PathVariable("studentId") Integer studentId, @RequestBody Student student){
        System.out.println("student has updated");
        System.out.println(String.format("%s %s", studentId, student));
    }
}
