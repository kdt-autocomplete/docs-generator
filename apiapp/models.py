from django.db import models
from django.contrib.auth.models import AbstractBaseUser, BaseUserManager, PermissionsMixin

class UserManager(BaseUserManager):
    def create_user(self, email, password, name, phone_number, **kwargs):

        if not email:
            raise ValueError('Users must have an email address')
        user = self.model(
            email=email,
            name=name,
            phone_number=phone_number
        )
        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_superuser(self, email=None, password=None, name=None, phone_number=None, **extra_fields):
        superuser = self.create_user(
            email=email,
            password=password,
            name=name,
            phone_number=phone_number
        )
        
        superuser.is_staff = True
        superuser.is_superuser = True
        superuser.is_active = True
        
        superuser.save(using=self._db)
        return superuser
    
# AbstractBaseUser를 상속해서 유저 커스텀
class User(AbstractBaseUser, PermissionsMixin):
    id = models.AutoField(primary_key=True)
    email = models.EmailField(max_length=100, unique=True, null=False, blank=False)
    password = models.CharField(max_length=200)
    name = models.CharField(max_length=50)
    phone_number = models.CharField(max_length=20)

	# 헬퍼 클래스 사용
    objects = UserManager()

	# 사용자의 username field는 email으로 설정 (이메일로 로그인)
    USERNAME_FIELD = 'email'

# docs table
class Docs(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE) # User 테이블의 ID와 연결
    birthdate = models.DateField(verbose_name='생년월일')
    address = models.CharField(max_length=255, verbose_name='주소')
    bank_name = models.CharField(max_length=50, verbose_name='은행명')
    bank_account = models.CharField(max_length=20, verbose_name='은행계좌')
    account_holder = models.CharField(max_length=50, verbose_name='예금주')
    unit_start_period = models.DateField(max_length=100, verbose_name='시작단위기간')
    unit_end_period = models.DateField(max_length=100, verbose_name='끝단위기간')

    class Meta:
        db_table = 'DOCS'