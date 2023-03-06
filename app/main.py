import os
import io
import time
import bcrypt
import pickle
import face_recognition
import numpy as np
from PIL import Image
from pymongo import MongoClient
from datetime import datetime, timedelta
from jose import jwt,JWTError
from typing import Union
from dotenv import load_dotenv
from os.path import join,dirname
from fastapi import FastAPI,Depends,HTTPException,status,Form,Request,UploadFile,File
from pydantic import BaseModel
from passlib.context import CryptContext
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm

dir = os.getcwd()
dotenv_path = join(dirname(__file__),'.env')
load_dotenv(dotenv_path)


DB = os.environ.get("DB")
COLLECTION = os.environ.get("COLLECTION")
SECRET_KEY = os.environ.get("SECRET_KEY")
ALGORITHM = os.environ.get("ALGORITHM")
ACCESS_TOKEN_EXPIRE_MINUTES = os.environ.get("ACCESS_TOKEN_EXPIRE_MINUTES")
MONGO_CONN = os.environ.get("MONGO_CONN")


client = MongoClient(MONGO_CONN)

app = FastAPI()

db = client[f"{DB}"]
collection = db[f"{COLLECTION}"]


oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")    
user_db = {}


class Token(BaseModel):
    access_token:str
    token_type:str

def token_check(token :str = Depends(oauth2_scheme)):
    try:
        user = jwt.decode(token,SECRET_KEY,algorithms=[ALGORITHM])
        print(user)
       
    except JWTError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,
             detail="Invalid Token",
             headers={"WWW-Authenticate": "Bearer"},
        )
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,
             detail="Expired Token",
             headers={"WWW-Authenticate": "Bearer"},
        )
    return user

def create_access_token(data: dict, expires_delta: Union[timedelta, None] = None):
    to_encode = data.copy()
    if expires_delta:   
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

def hash_func(plain_pass, hashed_pass,salt) -> bool:
    plain_pass_hashed = bcrypt.hashpw(plain_pass.encode('utf-8'), salt)
    if plain_pass_hashed == hashed_pass:
        return True

def serialize(known_face_encoding):
    return pickle.dumps(known_face_encoding)

async def file_to_nparray(file):
    file_content = await file.read()
    pil_image = Image.open(io.BytesIO(file_content))
    return np.array(pil_image)

@app.post("/token/face-auth", response_model = Token)
async def user_face_auth(username:str,file:UploadFile = File(...)):
    user = collection.find_one({"username":username})
    if not user:
        raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Cannot Find User.",
                headers={"WWW-Authenticate": "Bearer"},
            )
    unknown_img = await file_to_nparray(file)
    unknown_face_encoding = face_recognition.face_encodings(unknown_img)[0]
    known_face_encoding = pickle.loads(user["known_encoding"])
    result = face_recognition.compare_faces([known_face_encoding], unknown_face_encoding)
    if result[0] ==True:
        access_token_expires = timedelta(minutes=int(ACCESS_TOKEN_EXPIRE_MINUTES))
        access_token = create_access_token(
        data={"sub": user["username"]}, expires_delta=access_token_expires)
        return {"access_token":access_token,"token_type":"Bearer"}
    else:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Face Not Recognised",
            headers={"WWW-Authenticate": "Bearer"},
        )

@app.post("/token/cred-login", response_model = Token)
async def user_cred_login(img:bool,username:str,password:str,file:UploadFile=File(...)):
    user = collection.find_one({"username":username})

    if not user:
        raise  HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    pass_verified = hash_func(formData.password,user["password"],user["salt"])
    if pass_verified:
        access_token_expires = timedelta(minutes=int(ACCESS_TOKEN_EXPIRE_MINUTES))
        access_token = create_access_token(
        data={"sub": user["username"]}, expires_delta=access_token_expires)
        
        return {"access_token":access_token, "token_type":"Bearer"}
    else:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )

        



    
@app.get("/private")
async def user_private_info(user:None = Depends(token_check)):
    return {"msg":"This is a secret","user":user}

@app.get("/home")
async def user_home(user:str = Depends(token_check)):  
    return {"msg":user}

@app.get("/messi")
async def user_home():  
    return {"msg":"hello"}


@app.post("/register")
async def user_register(file:UploadFile=File(...),username:str = Form(), password:str = Form()):
    known_img = await file_to_nparray(file)
    salt = bcrypt.gensalt()
    hashed = bcrypt.hashpw(password.encode('utf-8'), salt)
    response = collection.find_one({"username":username})
    known_face_encoding = face_recognition.face_encodings(known_img)[0]
    serialized_encoding = serialize(known_face_encoding)
    if not response:
        collection.insert_one({"username":username, "password":hashed,"salt":salt,"created_at":str(time.time()).split(".")[-2],"known_encoding":serialized_encoding})
    else:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User already exist",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return {"msg":"User successfully Created"}

    
