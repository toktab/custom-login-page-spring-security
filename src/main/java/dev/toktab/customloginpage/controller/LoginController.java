package dev.toktab.customloginpage.controller;

import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.logout.SecurityContextLogoutHandler;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;

@Controller
public class LoginController {

    @Autowired
    private AuthenticationManager authenticationManager;

    @GetMapping("/login")
    public String login() {
        return "login";
    }

    @PostMapping("/custom-login")
    public String login(String username, String password, Model model, HttpServletResponse response) {
        UsernamePasswordAuthenticationToken authReq = new UsernamePasswordAuthenticationToken(username, password);
        Authentication auth = authenticationManager.authenticate(authReq);

        if (auth.isAuthenticated()) {
            SecurityContextHolder.getContext().setAuthentication(auth);
            // Create and add cookie here
            Cookie cookie = new Cookie("username", username);
            cookie.setMaxAge(60 * 60); // Cookie expiry time in seconds
            cookie.setPath("/");
            response.addCookie(cookie);

            // Set cache control headers
            response.setHeader("Cache-Control", "no-cache, no-store, must-revalidate");
            response.setHeader("Pragma", "no-cache");
            response.setDateHeader("Expires", 0);
            return "redirect:/home";
        } else {
            model.addAttribute("error", true);
            return "login";
        }
    }

    @GetMapping("/logout")
    public String logoutGet(Model model) {
        return "logout";
    }

    @PostMapping("/logout")
    public String logoutPost(@RequestParam("confirm") boolean confirm, HttpServletRequest request, HttpServletResponse response) {
        if (confirm) {
            Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
            String username = authentication != null ? authentication.getName() : "";
            request.getSession().invalidate();
            Cookie cookie = new Cookie("username", null);
            cookie.setMaxAge(0);
            cookie.setPath("/");
            response.addCookie(cookie);
            return "redirect:/login";
        } else {
            return "redirect:/home";
        }
    }
}