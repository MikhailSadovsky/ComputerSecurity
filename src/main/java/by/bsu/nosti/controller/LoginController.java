package by.bsu.nosti.controller;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.servlet.ModelAndView;

import by.bsu.nosti.entity.User;
import by.bsu.nosti.entity.UserModel;
import by.bsu.nosti.entity.UserRole;
import by.bsu.nosti.exception.DAOException;

@Controller
public class LoginController extends BaseController {

	@RequestMapping(value = "/login", method = RequestMethod.GET)
	public ModelAndView getLogin() {
		return new ModelAndView("login", "user", new User());
	}

	@RequestMapping(value = "/logout", method = RequestMethod.GET)
	public String getLogout(HttpServletRequest req, HttpServletResponse resp, Model model) {
		removeCookie("login", req, resp);
		return "index";
	}

	@RequestMapping(value = "/login", method = RequestMethod.POST)
	public String processLogin(@ModelAttribute("user") User user, BindingResult result, HttpServletRequest req,
			HttpServletResponse resp, Model model) {
		try {
			User userDb = userDAO.getUser(user.getLogin());
			if (userDb == null || !passwordEncoder.matches(user.getPassword(), userDb.getPassword())) {
				result.rejectValue("password", "wrongPassword", "Login or password is incorrect!");
			}
			if (result.hasErrors()) {
				return "login";
			} else {
				model.addAttribute("username", userDb.getLogin());
				return "login";
			}
		} catch (DAOException exception) {
			return "error";
		}
	}

	@RequestMapping(value = "/registration", method = RequestMethod.GET)
	public ModelAndView processRegister() {
		return new ModelAndView("registration", "person", new UserModel());

	}

	@RequestMapping(value = "/registration", method = RequestMethod.POST)
	public String processSubmit(@ModelAttribute("person") UserModel person, HttpServletRequest req,
			HttpServletResponse resp, Model model) {
		try {
			User user = new User();
			user.setEmail(person.getEmail());
			user.setLogin(person.getLogin());
			user.setPassword(passwordEncoder.encode(person.getPassword()));
			user.setRole(UserRole.User.ordinal());
			userDAO.create(user);
			model.addAttribute("currentuser", user.getLogin());
			if (user != null && user.getRole() == UserRole.Admin.ordinal()) {
				model.addAttribute("userResourceLinks", userResourceLinkDAO.retrieveAll());
				return "admin";
			}
			model.addAttribute("userResourceLinks", userResourceLinkDAO.getUserResourceLinkByUserId(user.getUserId()));
			return "index";
		} catch (DAOException exception) {
			return "error";
		}
	}
}
