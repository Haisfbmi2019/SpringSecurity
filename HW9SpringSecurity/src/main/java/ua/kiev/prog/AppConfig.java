package ua.kiev.prog;

import org.springframework.boot.CommandLineRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.method.configuration.GlobalMethodSecurityConfiguration;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.io.File;
import java.io.IOException;

@Configuration
@EnableGlobalMethodSecurity(prePostEnabled = true)
public class AppConfig extends GlobalMethodSecurityConfiguration {

    public static final String ADMIN = "admin";

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public CommandLineRunner demo(final PasswordEncoder encoder) {
        return strings -> {
            File storage = new File("src/main/XMLRepository.xml");
            if (!storage.isFile()) {
                try {
                    storage.createNewFile();
                } catch (IOException e) {
                    e.printStackTrace();
                }
            }
            UserService userService = new UserService();
            userService.addUser(ADMIN, encoder.encode("password"), UserRole.ADMIN, "", "");
            userService.addUser("user", encoder.encode("password"), UserRole.USER, "", "");
            userService.addUser("moderator", encoder.encode("1234"), UserRole.MODERATOR, "", "");

            Jaxb.toXML(userService);
        };
    }
}
