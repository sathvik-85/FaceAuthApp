import os
import time
import bcrypt
from pymongo import MongoClient
from datetime import datetime, timedelta
from jose import jwt,JWTError
from typing import Union
from dotenv import load_dotenv
from os.path import join,dirname
from fastapi import FastAPI,Depends,HTTPException,status,Form,Request
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
    plain_pass_bytes = plain_pass.encode('utf-8')
    plain_pass_hashed = bcrypt.hashpw(plain_pass_bytes, salt)
    if plain_pass_hashed == hashed_pass:
        return True


@app.post("/token", response_model = Token)
async def user_register(formData:OAuth2PasswordRequestForm = Depends()):
    user = collection.find_one({"username":formData.username})
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


@app.post("/register")
async def user_register(username:str = Form(), password:str = Form()):
    salt = bcrypt.gensalt()
    hashed = bcrypt.hashpw(str(password.encode()), salt)
    response = collection.find_one({"username":username})
    if not response:
        collection.insert_one({"username":username, "password":hashed,"salt":salt,"created_at":str(time.time()).split(".")[-2]})
    else:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User already exist",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return {"msg":"User successfully Created"}

    
