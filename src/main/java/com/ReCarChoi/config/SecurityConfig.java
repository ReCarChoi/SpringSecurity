package com.ReCarChoi.config;

import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

/**
 * @author 蔡江楠
 * @version 1.0
 * @date 2021/12/19 13:59
 * @description TODO
 */

@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.authorizeRequests().antMatchers("/").permitAll()
                .antMatchers("/level1/**").hasRole("vip1")
                .antMatchers("/level1/**").hasRole("vip2")
                .antMatchers("/level1/**").hasRole("vip3");
        //登录页面
        http.formLogin().loginPage("/toLogin").loginProcessingUrl("/login");
        http.csrf().disable();
        //记住我
        http.rememberMe().rememberMeParameter("remember");
        http.logout().logoutSuccessUrl("/");
    }

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.inMemoryAuthentication().passwordEncoder(new BCryptPasswordEncoder())
                .withUser("ReCarChoi")
                .password(new BCryptPasswordEncoder().encode("123456"))
                .roles("vip1", "vip2", "vip3")
                .and()
                .withUser("root")
                .password(new BCryptPasswordEncoder().encode("123456"))
                .roles("vip1", "vip2")
                .and()
                .withUser("author")
                .password(new BCryptPasswordEncoder().encode("123456"))
                .roles("vip1");
    }

}
