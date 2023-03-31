# This function is not intended to be invoked directly. Instead it will be
# triggered by an orchestrator function.
# Before running this sample, please:
# - create a Durable orchestration function
# - create a Durable HTTP starter function
# - add azure-functions-durable to requirements.txt
# - run pip install -r requirements.txt
import logging
import azure.functions as func
import azure.durable_functions as df


def entity_function(context: df.DurableEntityContext):
    # current_value should only ever be a valid refresh token or No Token Stored.
    current_value = context.get_state(lambda: 'No Token Stored')
    operation = context.operation_name
    logging.debug(f'PyLA[e]: Entity operation {context.operation_name} called.')
    if operation == 'get':
        context.set_result(current_value)
    if operation == 'set':
        current_value = context.get_input()
        # setting state is the most important part of this function
        #  as this is the bit the timer reads from.
        context.set_state(current_value)
        context.set_result(current_value)

main = df.Entity.create(entity_function)