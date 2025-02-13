# Taurpalin Course Management Tool - CS493 Portfolio Project

# Summary

I developed a complete RESTful API for Taurpalin, a lightweight course management tool that's an "alternative" to Canvas. The project utilized modern API design principles and was deployed on Google Cloud Platform using Google App Engine and Datastore. The API was built with Python 3 and utilizes Auth0 for secure user authentication. Through this project I gained hands-on experience in cloud application development, authentication services, and creating a fully functional API.


# Functionality

The REST API for Tarpaulin includes 13 endpoints, with most requiring authentication. Protected endpoints enforce security by validating a JWT passed as a Bearer token in the Authorization header. The application supports three user roles—admin, instructor, and student—each with specific permissions to manage course-related data. The summary of the 13 endpoints can be found below:


| | Functionality | Endpoint | Protection | Description |
| --- | --- | --- | --- | --- |
| 1 | User login | POST /users/login | Pre-created Auth0 users with username and password | Use Auth0 to issue JWTs. | 
| 2	| Get all users | GET /users | Admin only | Summary information of all 9 users. | No info about avatar or courses. | 
| 3	| Get a User | GET /users/:id | Admin. Or user with JWT matching id | Detailed info about the user, including avatar (if any) and courses (for instructors and students). | 
| 4	| Create/update a user's avatar | POST /users/:id/avatar | User with JWT matching id | Upload file to Google Cloud Storage. | 
| 5	| Get a user's avatar | GET /users/:id/avatar | User with JWT matching id | Read and return file from Google Cloud Storage. | 
| 6	| Delete a user's avatar | DELETE /users/:id/avatar | User with JWT matching id | Delete file from Google Cloud Storage. | 
| 7	| Create a course | POST /courses | Admin only | Create a course. | 
| 8	| Get all courses | GET /courses | Unprotected | Paginated using offset/limit. Page size is 3. Ordered by "subject." Doesn’t return info on course enrollment. | 
| 9	| Get a course | GET /courses/:id | Unprotected | Doesn’t return info on course enrollment. | 
| 10| Update a course | PATCH /courses/:id | Admin only | Partial update. | 
| 11| Delete a course | DELETE /courses/:id | Admin only | Delete course and delete enrollment info about the course. | 
| 12| Update enrollment in a course | PATCH /courses/:id/students | Admin. Or instructor of the course | Enroll or disenroll students from the course. | 
| 13| Get enrollment for a course | GET /courses/:id/students | Admin. Or instructor of the course | All students enrolled in the course. | 





# Testing the API
I tested the Tarpaulin REST API using Postman, utilizing both a Postman collection and an environment file designed for the project. The Postman collection included all 13 API endpoints, complete with pre-configured requests and example payloads to simulate various user interactions. The environment file streamlined testing by managing variables such as the API base URL and authentication tokens.

To validate the API’s functionality, I utilized Postman’s built-in tools to test protected endpoints by generating and passing JWT tokens as Bearer tokens in the Authorization header. This allowed me to verify that role-based access control was enforced correctly for admin, instructor, and student roles. Additionally, I used Postman’s response validation features to ensure the API returned appropriate status codes and data for all CRUD operations.