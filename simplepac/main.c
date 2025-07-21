#include <stdio.h>
#include <time.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <spawn.h>
#include <ptrauth.h>
#include <mach/mach.h>
#include <mach-o/fat.h>
#include <mach-o/loader.h>
#include <mach-o/dyld.h>

extern char **environ;

#define CRESET  "\x1B[0m"
#define CRED    "\x1B[31m"
#define CGREEN  "\x1B[32m"
#define CYELLOW "\x1B[33m"
#define CBLUE   "\x1B[34m"

typedef struct Contract {
    char text[128];
    char name[32];
    char date[8];

    void (*signature)(void); 
} Contract;

typedef void (*signature_fn)(void);
__attribute__ ((target("branch-protection=pac-ret+leaf+b-key")))
signature_fn sign_contract(uint64_t raw_ptr, uint64_t context) {
void *unauth = (void*)(uintptr_t)raw_ptr;
#if __has_feature(ptrauth_calls)
    void *signedp = ptrauth_sign_unauthenticated(unauth,
                                                 ptrauth_key_asib,
                                                 context);
    return (signature_fn)signedp;
#else
	return unauth;
#endif;
}

uint64_t get_image_base(char* image_name) {
	uint32_t count = _dyld_image_count();

	for(uint32_t i = 0; i < count; i++)
	{
		const char *dyld = _dyld_get_image_name(i);
		if(strstr(dyld, image_name) != NULL) {
			return (uint64_t)_dyld_get_image_header(i);
		}
	}
	return -1;
}

void print_menu(void) {
    puts("!! Welcome to Contract Studio Pro !!");
    puts("------------------------------");
    puts("1. Work on Contract");
    puts("2. Read Current Contract");
    puts("3. Finalize Contract");
    puts("4. Quit.");
    puts("------------------------------");
}


void init_wargame(void) {
    srand(time(NULL));
    setvbuf(stdout, NULL, _IONBF, 0);
}

void clear_stdin(void) {
    int ch;
    do {
        ch = getchar();    
    } while (ch != '\n' && ch != EOF);
}

void press_enter(void) {
    printf("Press enter to continue...");
    clear_stdin();
}

void winner() {
    pid_t pid;
    char *argv[] = { "zsh", NULL }; 

    int status = posix_spawn(&pid, "/bin/zsh", NULL, NULL, argv, environ);
    if (status == 0) {
        if (waitpid(pid, &status, 0) != -1) {
            printf("Child exited with status %d\n", WEXITSTATUS(status));
        } else {
            perror("waitpid");
        }
    } else {
        printf("posix_spawn failed: %d\n", status);
    }
}


uint32_t get_uint(void) {
    uint32_t value = 0;
    fflush(stdout);

    if (scanf("%u", &value) != 1) {
        value = 0;
    }

    clear_stdin();

    return value;
}

void work_on_contract(Contract * c) {
    time_t rawtime;
    struct tm * timeinfo;
    
    time(&rawtime);
    timeinfo = localtime (&rawtime);

    strftime(c->date, 8, "%m/%d", timeinfo);
    printf("Setting Date to: %s\n", c->date);

    printf("Enter text for contract:\n");
    gets(c->text);
    
    printf("Enter your name:\n");
    gets(c->name);

    printf("%sContract Updated!%s\n", CGREEN, CRESET);
}

void print_contract(Contract * c) {
    printf("--- Contract Reader Pro ---\n");
    printf("%s\n\n%s\n\nDATED: %s SIGNED: %p\n", c->text, c->name, c->date, c->signature);
    printf("---------------------------\n");
}

void finalize_contract(Contract * c) {
    printf("Signing contract! Using context: %s\n", c->date);
    press_enter();
    
    c->signature = sign_contract(*(uint64_t *)c->name, *(uint64_t *)c->date);
    printf("%sContract Signed!%s\n", CGREEN, CRESET);
}

void contract_menu() {
    Contract c;
    memset(&c, 0, sizeof(Contract));

    while(1) {
        print_menu(); 
        unsigned choice = get_uint();

        switch(choice) {
            case 1:
                work_on_contract(&c);
                break;

            case 2:
                print_contract(&c);
                break;

            case 3:
                finalize_contract(&c);
                break;

            case 4:
                return;
        }
    }
}

void main() {
    void* sp;
    asm volatile ("mov %0, sp" : "=r"(sp));
    printf("SP: %p\n", sp);

    uint64_t pie_base = get_image_base("simplepac");
    printf("pie_base=0x%llx\n", pie_base);
    init_wargame();
    contract_menu();
}
