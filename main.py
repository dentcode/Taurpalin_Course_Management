from flask import Flask, request, jsonify, send_file
from google.cloud import datastore, storage
from google.cloud.datastore.query import PropertyFilter

import io
import requests
import json

from six.moves.urllib.request import urlopen
from jose import jwt
from authlib.integrations.flask_client import OAuth

app = Flask(__name__)
app.secret_key = 'SECRET_KEY'

client = datastore.Client()

PHOTO_BUCKET = 'assignment6_delacrig'

LODGINGS = "lodgings"
USERS = 'users'
ERROR_400 = {"Error" : "The request body is invalid"}
LOGIN_ARGUMENTS = ['username', 'password']
ERROR_401 = {'Error': "Unauthorized"}
ERROR_404 = {"Error": "Not found"}
ERROR_403 = {"Error": "You don't have permission on this resource"}
ERROR_409 = {'Error': 'Enrollment data is invalid'}

COURSES = 'courses'
COURSES_ARGUMENTS = ['subject', 'number', 'title', 'term', 'instructor_id']
ENROLLMENTS = 'enrollments'

# Update the values of the following 3 variables
CLIENT_ID = 'liBLkbYXl9LdsSsjOpIovllAQdmc2VSW'
CLIENT_SECRET = '3Cb_VU67ch4alRpoY2A2SKNeXjkIBCBLRSqLZRYLyQper53O448zXhckVOEf0dGo'
DOMAIN = 'dev-gv1z233u1xlirjnj.us.auth0.com'
# For example
# DOMAIN = '493-24-spring.us.auth0.com'
# Note: don't include the protocol in the value of the variable DOMAIN

ALGORITHMS = ["RS256"]

oauth = OAuth(app)

auth0 = oauth.register(
    'auth0',
    client_id=CLIENT_ID,
    client_secret=CLIENT_SECRET,
    api_base_url="https://" + DOMAIN,
    access_token_url="https://" + DOMAIN + "/oauth/token",
    authorize_url="https://" + DOMAIN + "/authorize",
    client_kwargs={
        'scope': 'openid profile email',
    },
)

# This code is adapted from https://auth0.com/docs/quickstart/backend/python/01-authorization?_ga=2.46956069.349333901.1589042886-466012638.1589042885#create-the-jwt-validation-decorator

class AuthError(Exception):
    def __init__(self, error, status_code):
        self.error = error
        self.status_code = status_code


@app.errorhandler(AuthError)
def handle_auth_error(ex):
    response = jsonify(ex.error)
    response.status_code = ex.status_code
    return response

# Verify the JWT in the request's Authorization header
def verify_jwt(request):
    if 'Authorization' in request.headers:
        auth_header = request.headers['Authorization'].split()
        token = auth_header[1]
    else:
        raise AuthError({"code": "no auth header",
                            "description":
                                "Authorization header is missing"}, 401)
    
    jsonurl = urlopen("https://"+ DOMAIN+"/.well-known/jwks.json")
    jwks = json.loads(jsonurl.read())
    try:
        unverified_header = jwt.get_unverified_header(token)
    except jwt.JWTError:
        raise AuthError({"Error": "Unauthorized"}, 401)
    if unverified_header["alg"] == "HS256":
        raise AuthError({"Error": "Unauthorized"}, 401)
    rsa_key = {}
    for key in jwks["keys"]:
        if key["kid"] == unverified_header["kid"]:
            rsa_key = {
                "kty": key["kty"],
                "kid": key["kid"],
                "use": key["use"],
                "n": key["n"],
                "e": key["e"]
            }
    if rsa_key:
        try:
            payload = jwt.decode(
                token,
                rsa_key,
                algorithms=ALGORITHMS,
                audience=CLIENT_ID,
                issuer="https://"+ DOMAIN+"/"
            )
        except jwt.ExpiredSignatureError:
            raise AuthError({"code": "token_expired",
                            "description": "token is expired"}, 401)
        except jwt.JWTClaimsError:
            raise AuthError({"code": "invalid_claims",
                            "description":
                                "incorrect claims,"
                                " please check the audience and issuer"}, 401)
        except Exception:
            raise AuthError({"code": "invalid_header",
                            "description":
                                "Unable to parse authentication"
                                " token."}, 401)

        return payload
    else:
        raise AuthError({"code": "no_rsa_key",
                            "description":
                                "No RSA key in JWKS"}, 401)


@app.route('/')
def index():
    return "Please navigate to /users to use this API"\

    if request.method == 'POST':
        payload = verify_jwt(request)
        content = request.get_json()
        new_lodging = datastore.entity.Entity(key=client.key(LODGINGS))
        new_lodging.update({"name": content["name"], "description": content["description"],
          "price": content["price"]})
        client.put(new_lodging)
        return jsonify(id=new_lodging.key.id)
    else:
        return jsonify(error='Method not recogonized')

# Decode the JWT supplied in the Authorization header
@app.route('/decode', methods=['GET'])
def decode_jwt():
    payload = verify_jwt(request)
    return payload          
        

# Generate a JWT from the Auth0 domain and return it
# Request: JSON body with 2 properties with "username" and "password"
#       of a user registered with this Auth0 domain
# Response: JSON with the JWT as the value of the property id_token
@app.route('/' + USERS + '/login', methods=['POST'])
def login_user():
    content = request.get_json()
    if not is_valid_entity(content, LOGIN_ARGUMENTS):
        return ERROR_400, 400
    
    username = content["username"]
    password = content["password"]
    body = {'grant_type':'password','username':username,
            'password':password,
            'client_id':CLIENT_ID,
            'client_secret':CLIENT_SECRET
           }
    headers = { 'content-type': 'application/json' }
    url = 'https://' + DOMAIN + '/oauth/token'
    r = requests.post(url, json=body, headers=headers)
    r = r.text
    r_dict = json.loads(r)
    if "error" in r_dict:
        return ERROR_401, 401
    return {'token': r_dict['id_token']}, 200

# 2. Get list users
@app.route('/' + USERS, methods=['GET'])
def get_users():
    payload = verify_jwt(request)

    query = client.query(kind=USERS)
    users = list(query.fetch())

    for user in users:
        user['id'] = user.key.id
        if 'avatar' in user:
            user.pop('avatar')


    # Verify that the payload matches the admin role sub (can find in datastore)
    for user in users:
        if user['role'] == 'admin' and user['sub'] == payload['sub']:
            return users
    
    return ERROR_403, 403

# 3. Get a user
@app.route('/' + USERS + '/<int:id>', methods=['GET'])
def get_user(id):
    # Check if the JWT is missing or invalid, 401
    payload=verify_jwt(request)

    user_key = client.key(USERS, id)
    user = client.get(key=user_key)

    if user is None or user['sub'] != payload['sub']:
         if user['role'] != 'admin':
             return ERROR_403, 403
    user['id'] = user.key.id

    if 'avatar' in user and user['avatar'] == 'yes':
        user['avatar'] = request.url +'/avatar'
        user['avatar_url'] = user.pop('avatar')
    
    # For instructor reference COURSES kind and for student reference ENROLLMENTS kind when generating courses lists
    if user['role'] == 'instructor':
        instructor_query = client.query(kind=COURSES)
        instructor_query.add_filter(filter=PropertyFilter('instructor_id', '=', id))
        instructor_courses = list(instructor_query.fetch())
        courses_taught = []
        for course in instructor_courses:
            courses_taught.append(request.url_root + '/courses/' + str(course.key.id))
        user['courses'] = courses_taught

    if user['role'] == 'student':
        student_query = client.query(kind=ENROLLMENTS)
        student_query.add_filter(filter=PropertyFilter('student_id', '=', id))
        student_courses = list(student_query.fetch())
        courses_attended = []
        for course in student_courses:
            courses_attended.append(request.url_root + '/courses/' + str(course.key.id))
        user['courses'] = courses_attended
    
    if 'avatar' in user:
        user.pop('avatar')

    return user, 200

# 4. Create an avatar
@app.route('/' + USERS + '/<int:id>' + '/avatar', methods=['POST'])
def post_avatar(id):
    # Any files in the request will be available in request.files object
    # Check if there is an entry in request.files with the key 'file'
    print(request.files)
    if 'file' not in request.files:
        return (ERROR_400, 400)
    # Verify JWT 
    payload=verify_jwt(request)

    # 
    user_key = client.key(USERS, id)
    user = client.get(key=user_key)
    if user is None or user['sub'] != payload['sub']:
         if user['role'] != 'admin':
             return ERROR_403, 403
    # Set file_obj to the file sent in the request
    file_obj = request.files['file']
    # If the multipart form data has a part with name 'tag', set the
    # value of the variable 'tag' to the value of 'tag' in the request.
    # Note we are not doing anything with the variable 'tag' in this
    # example, however this illustrates how we can extract data from the
    # multipart form data in addition to the files.
    if 'tag' in request.form:
        tag = request.form['tag']
    # Create a storage client
    storage_client = storage.Client()
    # Get a handle on the bucket
    bucket = storage_client.get_bucket(PHOTO_BUCKET)
    # Create a blob object for the bucket with the name of the file
    blob = bucket.blob(str(id))
    # Position the file_obj to its beginning
    file_obj.seek(0)
    # Upload the file into Cloud Storage
    blob.upload_from_file(file_obj)

    # Add avatar property to user in datastore
    user['avatar'] = 'yes'
    client.put(user)
    
    return ({'avatar_url': request.url},200)

# 5. Get avatar
@app.route('/' + USERS + '/<int:id>' + '/avatar', methods=['GET'])
def get_avatar(id):
    # Verify JWT 
    payload=verify_jwt(request)

    # 
    user_key = client.key(USERS, id)
    user = client.get(key=user_key)
    if user is None or user['sub'] != payload['sub']:
         if user['role'] != 'admin':
             return ERROR_403, 403
    
    if 'avatar' not in user or user['avatar'] == 'no':
        return ERROR_404, 404
    
    storage_client = storage.Client()
    bucket = storage_client.get_bucket(PHOTO_BUCKET)
    # Create a blob with the given file name
    blob = bucket.blob(str(id))
    # Create a file object in memory using Python io package
    file_obj = io.BytesIO()
    # Download the file from Cloud Storage to the file_obj variable
    blob.download_to_file(file_obj)
    # Position the file_obj to its beginning
    file_obj.seek(0)
    # Send the object as a file in the response with the correct MIME type and file name
    return send_file(file_obj, mimetype='image/png', download_name=str(id))

# 6. Delete a user's avatar
@app.route('/' + USERS + '/<int:id>' + '/avatar', methods=['DELETE'])
def delete_avatar(id):
    # Verify JWT is valid
    payload=verify_jwt(request)

    # Verify JWT belongs to the user
    user_key = client.key(USERS, id)
    user = client.get(key=user_key)
    if user is None or user['sub'] != payload['sub']:
         if user['role'] != 'admin':
             return ERROR_403, 403

    # Verify user has an avatar
    if 'avatar' not in user or user['avatar'] == 'no':
        return ERROR_404, 404
    

    storage_client = storage.Client()
    bucket = storage_client.get_bucket(PHOTO_BUCKET)
    blob = bucket.blob(str(id))
    # Delete the file from Cloud Storage
    blob.delete()

    #Update avatar property
    # Add avatar property to user in datastore
    user['avatar'] = 'no'
    client.put(user)

    return '',204

# 7. Create a course
@app.route('/' + COURSES, methods=['POST'])
def post_course():
    content = request.get_json()
    request_url = request.url

    query = client.query(kind=USERS)
    results = list(query.fetch())

    # Verify JWT is valid
    payload=verify_jwt(request)

    # Verify JWT belongs to admin
    admin = False
    for r in results:
        if r['sub'] == payload['sub']:
            if r['role'] == 'admin':
                admin = True
    if not admin:
        return ERROR_403, 403

    # Verify request contains required attributes
    if not is_valid_entity(content, COURSES_ARGUMENTS):
        return ERROR_400, 400
    
    # Verify that the value of instructor_id corresponds to the id of an instructor
    for r in results:
        if r.key.id == content['instructor_id']:
            if r['role'] != 'instructor':
                return ERROR_400, 400

    # 
    new_key = client.key(COURSES)
    new_course = datastore.Entity(key=new_key)
    new_course.update({
        'subject': content['subject'],
        'instructor_id': content['instructor_id'], 
        'number': content['number'],
        'title': content['title'],
        'term': content['term']
    })
    client.put(new_course)
    new_course['id'] = new_course.key.id

    self_url = request_url + '/' + str(new_course['id'])

    return ({'id': new_course['id'],
             'instructor_id': content['instructor_id'],
             'subject': content['subject'], 
             'number': content['number'], 
             'title': content['title'],
             'term': content['term'],
             'self': self_url}, 201)

# 8. Get all courses
@app.route('/' + COURSES, methods=['GET'])
def get_courses():
    request_url = request.url
    page_limit = request.args.get('limit', 3)
    page_offset = request.args.get('offset', 0)
    page_limit = int(page_limit)
    page_offset = int(page_offset)

    course_query = client.query(kind=COURSES)
    courses = list(course_query.fetch(limit=page_limit, offset=page_offset))

    for course in courses:
        course['id'] = course.key.id
        course['self'] = request_url + '/' + str(course.key.id)
    
    new_page_offset = str(page_offset + page_limit)
    
    return ({'courses': courses,
             'next':  })

    
    



# 9. Get a course
@app.route('/' + COURSES + '/<int:id>', methods=['GET'])
def get_course(id):
    request_url = request.url

    course_key = client.key(COURSES, id)
    course = client.get(key=course_key)

    if course is None:
        return ERROR_404, 404

    course['id'] = course.key.id

    #self_url = request_url + '/' + str(course['id'])
    course['self'] = request_url

    return course, 200

# 10. Update a course
@app.route('/' + COURSES + '/<int:id>', methods=['PATCH'])
def update_course(id):
    content = request.get_json()
    request_url = request.url

    query = client.query(kind=USERS)
    users = list(query.fetch())

    # Verify JWT is valid
    payload=verify_jwt(request)

    # Verify JWT belongs to admin and course exists
    course_key = client.key(COURSES, id)
    course = client.get(key=course_key)
    if course is None:
        return ERROR_403, 403

    admin = False
    for user in users:
        if user['sub'] == payload['sub']:
            if user['role'] == 'admin':
                admin = True
    if not admin:
        return ERROR_403, 403

    # Verify the given instructor_id corresponds the id of an instructor  MAY BE AN ISSUE WITH USING USER['ID']
    if 'instructor_id' in content:
        for user in users:
            if user['role'] == 'instructor':
                if user.key.id != content['instructor_id']:
                    return ERROR_400, 400
    
    for property, property_value in content:
        course.update({property:property_value})
    client.put(course)
    course['id'] = course.key.id
    course['self'] = request_url
    return course, 200

# 11. Delete a course
@app.route('/' + COURSES + '/<int:id>', methods=['DELETE'])
def delete_course(id):
    query = client.query(kind=USERS)
    users = list(query.fetch())

    # Verify JWT is valid
    payload=verify_jwt(request)

    # Verify JWT belongs to admin and course exists
    course_key = client.key(COURSES, id)
    course = client.get(key=course_key)
    if course is None:
        return ERROR_403, 403

    admin = False
    for user in users:
        if user['sub'] == payload['sub']:
            if user['role'] == 'admin':
                admin = True
    if not admin:
        return ERROR_403, 403
    
    # Delete course
    client.delete(course_key)

    # Update ENROLLMENTS kind by deleting entries associated with course
    enrollment_query = client.query(kind=ENROLLMENTS)
    enrollment_query.add_filter(filter=PropertyFilter('course_id', '=', id))
    enrollment_query.keys_only()
    course_enrollment = list(enrollment_query.fetch())
    client.delete_multi(course_enrollment)

    return '',204

# 12. Update enrollment in a course
@app.route('/' + COURSES + '/<int:id>' + "/students", methods=['PATCH'])
def update_enrollment(id):
    query = client.query(kind=USERS)
    users = list(query.fetch())

    # Verify JWT is valid
    payload=verify_jwt(request)

    # Verify JWT belongs to admin and course exists
    course_key = client.key(COURSES, id)
    course = client.get(key=course_key)
    if course is None:
        return ERROR_403, 403

    admin = False
    for user in users:
        if user['sub'] == payload['sub']:
            if user['role'] == 'admin' or user.key.id == course['instructor_id']:
                admin = True
    if not admin:
        return ERROR_403, 403
    
    # Verify enrollment data is valid
    content = request.get_json()
    #    Verify that there is no common value between the arrays "add" and "remove"
    if content['add'] and content['remove']:
        for student in content['add']:
            if student in content['remove']:
                return ERROR_409, 409
    #    Verify that all values in the array "add" and "remove" correspond to the ID of a user with the role "student" in the kind "users"
    user_query = client.query(kind=USERS)
    user_query.add_filter(filter=PropertyFilter('role', '=', 'student'))
    student_users = list(user_query.fetch())
    for student in content['add']:
        if student not in student_users:
            return ERROR_409
    for student in content['remove']:
        if student not in student_users:
            return ERROR_409
    
    # Add enrollment
    for student in content['add']:
        # get course enrollment and update enrollment if student not already enrolled in course
        enrollment_query = client.query(kind=ENROLLMENTS)
        enrollment_query.add_filter(filter=PropertyFilter('course_id', '=', id))
        enrollment_query.add_filter(filter=PropertyFilter('student_id', '=', student))
        course_enrollment = list(enrollment_query.fetch())
        if not course_enrollment:
            new_key = client.key(ENROLLMENTS)
            new_enrollment = datastore.Entity(key=new_key)
            new_enrollment.update({
                'course_id': id,
                'student_id': student
            })
            client.put(new_enrollment)
    
    # Remove enrollment
    for student in content['remove']:
        # get course enrollment and update enrollment if student enrolled in course
        enrollment_query = client.query(kind=ENROLLMENTS)
        enrollment_query.add_filter(filter=PropertyFilter('course_id', '=', id))
        enrollment_query.add_filter(filter=PropertyFilter('student_id', '=', student))
        course_enrollment = list(enrollment_query.fetch())
        for entry in course_enrollment:
            enrollment_key = client.key(ENROLLMENTS, entry.key.id)
            client.delete(enrollment_key)
        
    return '', 200

 
# 13. Get enrollment in a course
@app.route('/' + COURSES + '/<int:id>' + "/students", methods=['GET'])
def get_enrollment(id):
    query = client.query(kind=USERS)
    users = list(query.fetch())

    # Verify JWT is valid
    payload=verify_jwt(request)

    # Verify JWT belongs to admin and course exists
    course_key = client.key(COURSES, id)
    course = client.get(key=course_key)
    if course is None:
        return ERROR_403, 403

    admin = False
    for user in users:
        if user['sub'] == payload['sub']:
            if user['role'] == 'admin' or user.key.id == course['instructor_id']:
                admin = True
    if not admin:
        return ERROR_403, 403
    
    # Create enrollment list for course
    enrollment_query = client.query(kind=ENROLLMENTS)
    enrollment_query.add_filter(filter=PropertyFilter('course_id', '=', id))
    course_enrollment = list(enrollment_query.fetch())
    student_enrollment = []
    for entry in course_enrollment:
        student_enrollment.append(entry['student_id'])
    
    return student_enrollment, 200
##################################################### HELPER FUNCTIONS #########################################



def is_valid_entity(entity, attributes):
    """
    If the request is missing any of the required attributes returns False. Otherwise returns True.
    """
    for attribute in attributes:
        if attribute not in entity:
            return False
    return True





if __name__ == '__main__':
    app.run(host='127.0.0.1', port=8080, debug=True)

