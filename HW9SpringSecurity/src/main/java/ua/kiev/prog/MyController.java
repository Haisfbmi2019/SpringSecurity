package ua.kiev.prog;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.User;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;

import java.util.Collection;
import java.util.List;
import java.util.Objects;

@Controller
public class MyController {
    @Autowired
    private PasswordEncoder passwordEncoder;

    @RequestMapping("/")
    public String index(Model model){
        User user = getCurrentUser();

        String login = user.getUsername();
        CustomUser dbUser = Objects.requireNonNull(Jaxb.fromXML()).findByLogin(login);

        model.addAttribute("login", login);
        model.addAttribute("roles", user.getAuthorities());

        model.addAttribute("admin", isAdmin(user)||isModerator(user));
        model.addAttribute("email", dbUser.getEmail());
        model.addAttribute("phone", dbUser.getPhone());
        return "index";
    }

    @RequestMapping(value = "/update", method = RequestMethod.POST)
    public String update(@RequestParam(required = false) String email,
                         @RequestParam(required = false) String phone) {
        UserService userService;
        userService= Jaxb.fromXML();
        User user = getCurrentUser();
        String login = user.getUsername();
        assert userService != null;
        userService.updateUser(login, email, phone);
        Jaxb.toXML(userService);
        return "redirect:/";
    }

    @RequestMapping(value = "/newuser", method = RequestMethod.POST)
    public String update(@RequestParam String login,
                         @RequestParam String password,
                         @RequestParam(required = false) String email,
                         @RequestParam(required = false) String phone,
                         Model model) {
        String passHash = passwordEncoder.encode(password);
         UserService userService = Jaxb.fromXML();
        assert userService != null;
        if ( ! userService.addUser(login, passHash, UserRole.USER, email, phone)) {
            model.addAttribute("exists", true);
            model.addAttribute("login", login);

            return "register";
        }
        Jaxb.toXML(userService);
        return "redirect:/";
    }

    @RequestMapping(value = "/delete", method = RequestMethod.POST)
    public String delete(@RequestParam(name = "toDelete[]", required = false) List<String> login,
                         Model model) {
        UserService userService = Jaxb.fromXML();
        assert userService != null;
        userService.deleteUsers(login);
        model.addAttribute("users", userService.getAllUsers());
        Jaxb.toXML(userService);
        return "admin";
    }

    @RequestMapping("/login")
    public String loginPage() {
        return "login";
    }

    @RequestMapping("/register")
    public String register() {
        return "register";
    }

    @RequestMapping("/admin")

    public String admin(Model model) {
        User user = getCurrentUser();
        UserService userService = Jaxb.fromXML();
        assert userService != null;
        model.addAttribute("users", userService.getAllUsers());
        model.addAttribute("admin", isAdmin(user));
        model.addAttribute("moderator", isModerator(user));

        return "admin";
    }

    @RequestMapping("/unauthorized")
    public String unauthorized(Model model){
        User user = (User)SecurityContextHolder.getContext().getAuthentication().getPrincipal();
        model.addAttribute("login", user.getUsername());
        return "unauthorized";
    }

    private User getCurrentUser() {
        return (User)SecurityContextHolder
                .getContext()
                .getAuthentication()
                .getPrincipal();
    }

    private boolean isAdmin(User user) {
        Collection<GrantedAuthority> roles = user.getAuthorities();

        for (GrantedAuthority auth : roles) {
            if ("ROLE_ADMIN".equals(auth.getAuthority()))
                return true;
        }
        return false;
    }

    private boolean isModerator(User user) {
        Collection<GrantedAuthority> roles = user.getAuthorities();

        for (GrantedAuthority auth : roles) {
            if ("ROLE_MODERATOR".equals(auth.getAuthority()))
                return true;
        }
        return false;
    }
}
