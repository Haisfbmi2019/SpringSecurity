package ua.kiev.prog;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlRootElement;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
@XmlRootElement(name = "xml")
@Component
public class UserService {
    @XmlElement(name = "users")
  List<CustomUser> list = new ArrayList<>();

    public UserService() {
    }

   // @Transactional(readOnly = true)
    public List<CustomUser> getAllUsers() {
        return this.list;
    }

  //  @Transactional(readOnly = true)
    public CustomUser findByLogin(String login) {
        for (CustomUser customUser:list) {
            if(customUser.getLogin().equalsIgnoreCase(login)){
            return customUser;
            }
        }
        return null;
    }

  //  @Transactional
    public void deleteUsers(List<String> login) {
       List<CustomUser> toDelete = new ArrayList<>();
       for (String log:login){
           toDelete.add(findByLogin(log));
       }
       list.removeAll(toDelete);
    }

  //  @Transactional
    public boolean addUser(String login, String passHash,
                           UserRole role, String email,
                           String phone) {


        CustomUser user = new CustomUser(login, passHash, role, email, phone);
        list.add(user);
          return findByLogin(login) != null;
    }

   // @Transactional
    public void updateUser(String login, String email, String phone) {
        CustomUser user = findByLogin(login);
        if (user == null)
            return;
        user.setEmail(email);
        user.setPhone(phone);
    }

    @Override
    public String toString() {
        return "UserService{" +
                "list=" + list +
                '}';
    }
}
