import unittest
import turbogears
from turbogears import testutil

from funcweb.widget_automation import WidgetListFactory,RemoteFormAutomation,RemoteFormFactory
from funcweb.widget_validation import WidgetSchemaFactory

class TestWidgetListFactory(unittest.TestCase):
    
    def setUp(self):
        self.widget_factory = WidgetListFactory(self.get_test_default_args(),minion="myminion",module="mymodule",method="my_method")
    
        
    def tearDown(self):
        pass

    def test_default_args(self):
        compare_with = self.get_test_default_args()
        widget_list=self.widget_factory.get_widgetlist()
        
        #print "The widget list is like :",widget_list

        for argument_name,argument_options in compare_with.iteritems():
            assert widget_list.has_key(argument_name) == True
            #print "The argument name is :",argument_name
            #because some of them dont have it like boolean
            if argument_options.has_key('default'):
                assert argument_options['default'] == getattr(widget_list[argument_name],'default')

            if argument_options.has_key("description"):
                assert argument_options['description']==getattr(widget_list[argument_name],'help_text')

            if argument_options.has_key("options"):
                assert argument_options['options'] == getattr(widget_list[argument_name],"options")
            
        #that should be enough
    def test_get_widgetlist_object(self):
        compare_with = self.get_test_default_args()
        widget_list_object = self.widget_factory.get_widgetlist_object()
        
        #print widget_list_object
    
        all_fields = [getattr(field,"name") for field in widget_list_object]
        #print all_fields
        for argument_name in compare_with.keys():
            print argument_name
            assert argument_name in all_fields
            #print getattr(widget_list_object,argument_name)


    def test_remote_form(self):
        schema_factory = WidgetSchemaFactory(self.get_test_default_args())
        schema_validator=schema_factory.get_ready_schema()
        widget_list_object = self.widget_factory.get_widgetlist_object()
        remote_form = RemoteFormAutomation(widget_list_object,schema_validator)
        #print remote_form

    def test_remote_form_factory(self):
        from turbogears.view import load_engines
        load_engines()
       
        # WidgetsList object
        widget_list_object = self.widget_factory.get_widgetlist_object()
        #print widget_list_object
        remote_form = RemoteFormFactory(widget_list_object).get_remote_form()

        #it is a key,value dict
        widget_list=self.widget_factory.get_widgetlist()
        #print widget_list
        all_fields = [getattr(field,"name") for field in remote_form.fields]
        #print all_fields
        #will check if the remote form object hass all the names in it
        for argument_name in widget_list.items():
            argument_name in all_fields 


        #print remote_form.render()
    
    def get_test_default_args(self):
        return {
                'string_default':{
                    'type':'string',
                    'default':'default string',
                    'optional':False,
                    'description':'default description'
                    },
                'int_default':{
                    'type':'int',
                    'default':'default int',
                    'optional':False,
                    'description':'default description'
                   },
                #no sense to have default
                'boolean_default':{
                    'type':'boolean',
                    'optional':False,
                    'description':'default description'
                   },
                'float_default':{
                    'type':'float',
                    'default':'default float',
                    'optional':False,
                    'description':'default description'
                   
                    },
                'hash_default':{
                    'type':'hash',
                    'default':'default hash',
                    'optional':False,
                    'description':'default description'
                   
                    },
                'list_default':{
                    'type':'list',
                    'default':'default list',
                    'optional':False,
                    'description':'default description'
                   
                    },
                #will be converted to dropdown
                'special_string':{
                    'type':'string',
                    'default':'myfirst',
                    'options':['myfirst','mysecond','mythird'],
                    'optional':False,
                    'description':'default dropdown list'
                    }
                
                }

