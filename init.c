// init: The initial user-level program

#include "types.h"
#include "stat.h"
#include "user.h"
#include "fcntl.h"
#include "bcrypt.h"
#define MAX_BUFFER_SIZE 100

char *argv[] = { "sh", 0 };

void setPassword(int fd) {

  char newPassword[MAX_BUFFER_SIZE];
  char confirmedPassword[MAX_BUFFER_SIZE];

  int randomNumbers[4];
  uchar salt[16];

  int i, j;

  // prompt to enter password
  printf(0, "Enter password: ");
  gets(newPassword, MAX_BUFFER_SIZE);
  printf(0, "Retype the password: ");
  gets(confirmedPassword, MAX_BUFFER_SIZE);

  // check that the two passwords match
  if (strcmp(newPassword, confirmedPassword) == 0) { // passwords match, proceed
    printf(0, "Password successfully set. You may now use it to log in.\n");
    for (i = 0; i < 4; i++) {
      randomNumbers[i] = random();
    }
    for (j = 0; j < 16; j+=4) {
      *((int*)salt+j) = randomNumbers[j/4];
    } 
    write(fd, salt, BCRYPT_HASHLEN); // write salt
    write(fd, bcrypt(newPassword, salt), BCRYPT_HASHLEN); // write hashed password
  }
  else { // passwords do not match
    printf(0, "Passwords do not match. Try again.\n");
    setPassword(fd);
  }

}

void login() {

  // open passwords file
  int fd = open("passwords", O_RDONLY);
  uchar salt[BCRYPT_HASHLEN];
  uchar hashed[BCRYPT_HASHLEN];
  char password[MAX_BUFFER_SIZE];

  // read salt and hash in file
  read(fd, salt, BCRYPT_HASHLEN);
  read(fd, hashed, BCRYPT_HASHLEN);

  // prompt user for password
  printf(0, "Enter password: ");
  gets(password, MAX_BUFFER_SIZE);

  // check password
  if(bcrypt_checkpass(password, salt, hashed) != 0) { // incorrect password
    printf(0, "Incorrect password. Please enter correct password: ");
    gets(password, MAX_BUFFER_SIZE);
  }
  else { // correct password
    printf(0, "Logging in...\n");
  }
  
}

int
main(void)
{

  // no password created
  int pass_created = 0;

  int pid, wpid;

  if(open("console", O_RDWR) < 0){
    mknod("console", 1, 1);
    open("console", O_RDWR);
  }
  dup(0);  // stdout
  dup(0);  // stderr

  int fd = open("passwords", O_RDWR);
  if (fd < 0) { // no password
    close(fd);
    fd = open("passwords", O_CREATE|O_RDWR);
  }
  else { // password already made
    pass_created = 1; 
  }

  while (!pass_created) {
    printf(0, "No password set. Please choose one.\n");
    setPassword(fd);
    pass_created = 1;
  }

  login();

  close(fd);

  // can use xv6

  for(;;){
    printf(1, "init: starting sh\n");
    pid = fork();
    if(pid < 0){
      printf(1, "init: fork failed\n");
      exit();
    }
    if(pid == 0){
      exec("sh", argv);
      printf(1, "init: exec sh failed\n");
      exit();
    }
    while((wpid=wait()) >= 0 && wpid != pid)
      printf(1, "zombie!\n");
  }
}
