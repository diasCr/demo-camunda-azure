package ch.cristiano.demo.webapp;

import org.camunda.bpm.spring.boot.starter.annotation.EnableProcessApplication;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

@SpringBootApplication
@EnableProcessApplication
public class DemoSpringbootWebappApplication {

	public static void main(String[] args) {
		System.setProperty("https.proxyHost", "127.0.0.1");
		System.setProperty("https.proxyPort", "8888");
		SpringApplication.run(DemoSpringbootWebappApplication.class, args);
	}

}
