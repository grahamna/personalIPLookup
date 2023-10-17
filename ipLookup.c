#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>

void lookup(const char *ipAddress) {
     const char *links[] = {
        "https://www.virustotal.com/gui/ip-address/",
        "https://talosintelligence.com/reputation_center/lookup?search=",
        "https://otx.alienvault.com/indicator/ip/",
        "https://www.shodan.io/host/",
        "https://www.abuseipdb.com/check/"
    };
    char command[512];

#ifdef _WIN32
    // Windows-specific code
    for (int i = 0; i < sizeof(links) / sizeof(links[0]); i++) {
        snprintf(command, sizeof(command), "start %s%s", links[i], ipAddress);
        system(command);
    }
#else
    // Linux-specific code
    for (int i = 0; i < sizeof(links) / sizeof(links[0]); i++) {
        snprintf(command, sizeof(command), "xdg-open %s%s", links[i], ipAddress);
        system(command);
    }
#endif
}

int main() {
    while (1) {
        char ipAddress[20];
        printf("Enter IP (or 'q' to exit): ");
        if (fgets(ipAddress, sizeof(ipAddress), stdin) == NULL) {
            printf("Input char num was too large");
        }
        ipAddress[strcspn(ipAddress, "\n")] = '\0';

        const char *exitStatement = "q";
        if (strcmp(ipAddress, exitStatement) == 0) {
            printf("Exiting\n");
            break;
        }

        printf("Looking up IP %s\n", ipAddress);
        lookup(ipAddress);
    }

    return 0;
}