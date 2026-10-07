from fastapi import FastAPI, Depends, HTTPException
from sqlalchemy.orm import Session
from database import engine, Base, get_db
import models, schemas, auth
from fastapi.security import OAuth2PasswordRequestForm, OAuth2PasswordBearer

Base.metadata.create_all(bind=engine)

app = FastAPI(title="Auth System")


@app.get("/health")
def health():
    return {"status": "ok"}


@app.post("/register", response_model=schemas.UserOut)
def register(user: schemas.UserCreate, db: Session = Depends(get_db)):
    existing = db.query(models.User).filter(models.User.email == user.email).first()
    if existing:
        raise HTTPException(status_code=400, detail="Email already registered")

    new_user = models.User(
        email=user.email,
        hashed_password=auth.hash_password(user.password),
    )
    db.add(new_user)
    db.commit()
    db.refresh(new_user)
    return new_user


@app.post("/login", response_model=schemas.Token)
def login(form: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    user = db.query(models.User).filter(models.User.email == form.username).first()
    if not user or not auth.verify_password(form.password, user.hashed_password):
        raise HTTPException(status_code=401, detail="Incorrect email or password")

    return {
        "access_token": auth.create_access_token(user.email),
        "refresh_token": auth.create_refresh_token(user.email),
        "token_type": "bearer",
    }



oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")


def get_current_user(
    token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)
):
    email = auth.decode_token(token)
    if email is None:
        raise HTTPException(status_code=401, detail="Invalid or expired token")

    user = db.query(models.User).filter(models.User.email == email).first()
    if user is None:
        raise HTTPException(status_code=401, detail="User not found")
    return user


@app.get("/me", response_model=schemas.UserOut)
def read_me(current_user: models.User = Depends(get_current_user)):
    return current_user



@app.post("/refresh", response_model=schemas.Token)
def refresh(body: schemas.RefreshRequest, db: Session = Depends(get_db)):
    email = auth.decode_token(body.refresh_token, expected_type="refresh")
    if email is None:
        raise HTTPException(status_code=401, detail="Invalid or expired refresh token")

    user = db.query(models.User).filter(models.User.email == email).first()
    if user is None:
        raise HTTPException(status_code=401, detail="User not found")

    return {
        "access_token": auth.create_access_token(user.email),
        "refresh_token": auth.create_refresh_token(user.email),
        "token_type": "bearer"
    }