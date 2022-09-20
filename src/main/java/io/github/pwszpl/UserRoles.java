package io.github.pwszpl;

import javax.management.MBeanServerConnection;
import javax.management.MalformedObjectNameException;
import javax.management.ObjectName;
import javax.management.remote.JMXConnector;
import javax.management.remote.JMXConnectorFactory;
import javax.management.remote.JMXServiceURL;
import javax.naming.Context;
import java.io.IOException;
import java.net.MalformedURLException;
import java.util.*;
import java.util.function.BiFunction;
import java.util.stream.Collectors;

/**
 * Class used as wrapper for WebLogic Server identity providers. It uses JMX to communicate with WLS providers beans to list users and check authorizations
 */
public class UserRoles {

    MBeanServerConnection connection;
    JMXConnector connector;
    static final ObjectName service;

    Map<String,ObjectName> identityProviders;
    static final ObjectName MBTservice;

    // Initializing the object name for DomainRuntimeServiceMBean
    static {
        try {
            service = new ObjectName(
                    "com.bea:Name=DomainRuntimeService,Type=weblogic.management.mbeanservers.domainruntime.DomainRuntimeServiceMBean");
            MBTservice = new ObjectName("com.bea:Name=MBeanTypeService,Type=weblogic.management.mbeanservers.MBeanTypeService");
        }catch (MalformedObjectNameException e) {
            throw new AssertionError(e.getMessage());
        }
    }

    public UserRoles(String hostname, String portString, String username, String password){
        try {
            initConnection(hostname,portString,username,password);
            getIdentityProviders();
        } catch (IOException e) {
            System.out.println(e.getLocalizedMessage());
        }

    }

    public UserRoles(MBeanServerConnection connection){
        this.connection = connection;
        getIdentityProviders();
    }

    /*
     * Initialize connection to the Domain Runtime MBean Server
     */
    private void initConnection(String hostname, String portString,
                                String username, String password) throws IOException,
            MalformedURLException {
        String protocol = "t3";
        Integer portInteger = Integer.valueOf(portString);
        int port = portInteger.intValue();
        String jndiroot = "/jndi/";
        String mserver = "weblogic.management.mbeanservers.domainruntime";
        JMXServiceURL serviceURL = new JMXServiceURL(protocol, hostname,
                port, jndiroot + mserver);
        Hashtable h = new Hashtable();
        h.put(Context.SECURITY_PRINCIPAL, username);
        h.put(Context.SECURITY_CREDENTIALS, password);
        h.put(JMXConnectorFactory.PROTOCOL_PROVIDER_PACKAGES, "weblogic.management.remote");
        connector = JMXConnectorFactory.connect(serviceURL, h);
        connection = connector.getMBeanServerConnection();
    }

    /*
    initialize identity providers
     */
    private void getIdentityProviders() {
        ObjectName domainRuntimeName = getBeanAttribute(service,"DomainConfiguration",ObjectName.class);
        ObjectName SecurityConfiguration = getBeanAttribute(domainRuntimeName,"SecurityConfiguration",ObjectName.class);
        ObjectName defaultRealm = getBeanAttribute(SecurityConfiguration,"DefaultRealm",ObjectName.class);
        ObjectName[] mappers = getBeanAttribute(defaultRealm,"AuthenticationProviders",ObjectName[].class);

        if(mappers != null){
            identityProviders = new HashMap<>();
            for(ObjectName mapper : mappers){
                identityProviders.put(getBeanAttribute(mapper,"Name",String.class),mapper);
            }
        }
    }

    /**
     * Methods check if user is a member of group for chosen identity provider
     * @param provider - valid provider name
     * @param user - user name
     * @param group - group name
     * @return - result of memberships verification
     */
    public boolean isMember(String provider,String user,String group){
        return invokeBeanMethod(identityProviders.get(provider),"isMember",Boolean.class,group,user);
    }

    /**
     * Method checks if a user exists for chosen identity provider
     * @param provider - valid provider name
     * @param user - user name
     * @return - true if user exists
     */
    public boolean userExists(String provider,String user){
        return invokeBeanMethod(identityProviders.get(provider),"userExists",Boolean.class,user);
    }

    /**
     * Method checks if a group exists for chosen identity provider
     * @param provider - valid provider name
     * @param group - group name
     * @return - true if group exists
     */
    public boolean groupExists(String provider,String group){
        return invokeBeanMethod(identityProviders.get(provider),"groupExists",Boolean.class,group);
    }

    /**
     * Method returns list of identity providers found in WLS server
     * @return
     */
    public List<String> listIdentityProviders(){
        return identityProviders.entrySet().stream().map(e -> e.getKey()).collect(Collectors.toList());
    }

    /**
     * Method return list of users found for identity provider in WLS server
     * @param provider - valid provider name
     * @param filter - user regex
     * @param limit - size of return result set
     * @return - list of users
     */
    public List<String> listUsers(String provider,String filter, int limit){
        String usersCur = invokeBeanMethod(identityProviders.get(provider),"listUsers",String.class,filter,limit);
        List<String> users = traverseThroughCursor(identityProviders.get(provider),usersCur,String.class,
                (e,v) -> {
                    return invokeBeanMethod(v,"getCurrentName",String.class,e);
                }
                );
        return users;
    }

    /**
     * Method return list of groups found for identity provider in WLS server
     * @param provider - valid provider name
     * @param filter - user regex
     * @param limit - size of return result set
     * @return - list of groups
     */
    public List<String> listGroups(String provider,String filter, int limit){
        String groupsCur = invokeBeanMethod(identityProviders.get(provider),"listGroups",String.class,filter,limit);
        List<String> groups = traverseThroughCursor(identityProviders.get(provider),groupsCur,String.class,
                (e,v) -> {
                    return invokeBeanMethod(v,"getCurrentName",String.class,e);
                }
        );
        return groups;
    }

    private <T> T getBeanAttribute(ObjectName bean, String attribute,Class<T> c){
        try {
            Object o = connection.getAttribute(bean,attribute);
            return c.cast(o);
        } catch (Exception e) {
            System.out.println(e.getLocalizedMessage());
        }
        return null;
    }

    private void invokeBeanMethod(ObjectName bean, String methodName, Object... params) {
        List<String> classes = Arrays.stream(params).map(e -> e.getClass().getCanonicalName()).collect(Collectors.toList());
        try {
            connection.invoke(bean,methodName, Arrays.stream(params).toArray(), classes.toArray(new String[0]));
        } catch (Exception e) {
            System.out.println(e.getLocalizedMessage());
        }
    }
    private <T> T invokeBeanMethod(ObjectName bean, String methodName, Class <T> cl,Object... params) {
        List<String> classes = Arrays.stream(params).map(e -> e.getClass().getCanonicalName()).collect(Collectors.toList());
        try {
            return cl.cast(connection.invoke(bean,methodName, Arrays.stream(params).toArray(), classes.toArray(new String[0])));
        } catch (Exception e) {
            System.out.println(e.getLocalizedMessage());
        }
        return null;
    }

    private <T> List<T> traverseThroughCursor(ObjectName bean, String cursor, Class <T> cl, BiFunction<String,ObjectName,T> m){
        List<T> list = new ArrayList<T>();
        while(invokeBeanMethod(bean,"haveCurrent",Boolean.class,cursor)){
            list.add(m.apply(cursor,bean));
            invokeBeanMethod(bean,"advance",cursor);
        }
        return list;
    }

    public static void main(String[] args) throws Exception {
        UserRoles s = new UserRoles(args[0],args[1],args[2],args[3]);

        s.listIdentityProviders().forEach(e -> System.out.println(e));
        s.listUsers(s.listIdentityProviders().get(0),"*",10).forEach(e -> System.out.println(e));
        s.listGroups(s.listIdentityProviders().get(0),"*",10).forEach(e -> System.out.println(e));
    }
}