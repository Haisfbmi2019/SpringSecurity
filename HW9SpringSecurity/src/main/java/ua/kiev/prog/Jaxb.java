package ua.kiev.prog;

import org.springframework.stereotype.Component;

import javax.xml.bind.JAXBContext;
import javax.xml.bind.JAXBException;
import javax.xml.bind.Marshaller;
import javax.xml.bind.Unmarshaller;
import java.io.File;
@Component
public class Jaxb {

    public static void toXML(UserService userService){
        try {
            JAXBContext jaxbC = JAXBContext.newInstance(UserService.class);
            Marshaller marSh = jaxbC.createMarshaller();
            marSh.setProperty(Marshaller.JAXB_FORMATTED_OUTPUT, true);
            marSh.marshal(userService, new File(Path.path()));
        } catch (JAXBException e) {
            e.printStackTrace();
        }
    }

    public static UserService fromXML(){
        try {
            JAXBContext jaxbContext = JAXBContext.newInstance(UserService.class);
            Unmarshaller unmarshaller = jaxbContext.createUnmarshaller();
            return (UserService) unmarshaller.unmarshal(new File(Path.path()));
        } catch (JAXBException e) {
            e.printStackTrace();
        }
        return null;
    }
}
