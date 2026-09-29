
from fastapi import APIRouter, Depends
from .. import models, schemas
from .deps import get_current_user

router = APIRouter(prefix="/auth", tags=["auth"])


@router.get("/me", response_model=schemas.UserOut)
def me(user: models.User = Depends(get_current_user)):
    return user
